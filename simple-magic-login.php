<?php
/**
 * Plugin Name: Simple Magic Login
 * Description: Email login links with a password login fallback. Activate on individual multisite sites.
 * Version: 0.1.0
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 * Text Domain: simple-magic-login
 *
 * A minimal reimplementation of the Magic Login workflow by HandyPlugins.
 */

namespace SimpleMagicLogin;

defined( 'ABSPATH' ) || exit;

/** Diagnostics go to PHP's configured error log; never include credentials or mail bodies. */
function log_event( $event, $context = array() ) {
	// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Operational delivery diagnostics are documented and redact credentials.
	error_log( '[simple-magic-login] ' . wp_json_encode( array_merge( array( 'site_id' => get_current_blog_id(), 'event' => $event ), $context ) ) );
}

function eligible( $user, &$reason = null ) {
	if ( ! $user instanceof \WP_User || ( is_multisite() && ( ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) || $user->spam || $user->deleted ) ) ) {
		$reason = $user ? 'not_site_member_or_disabled' : 'unknown_email';
		return false;
	}
	// Email links cannot complete the Two Factor plugin's challenge flow.
	if ( class_exists( '\Two_Factor_Core' ) && \Two_Factor_Core::is_user_using_two_factor( $user->ID ) ) {
		$reason = 'two_factor_enabled';
		return false;
	}
	$reason = 'authentication_filter_denied';
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Apply the existing WordPress account restriction hook.
	$checked = apply_filters( 'wp_authenticate_user', $user, '' );
	return $checked instanceof \WP_User && $checked->ID === $user->ID
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Public plugin hook uses the full simple_magic_login prefix.
		&& (bool) apply_filters( 'simple_magic_login_allowed', true, $user );
}

function meta_key() {
	return '_simple_magic_login_' . get_current_blog_id();
}

function create_link( $user, $redirect, &$code = null ) {
	$code = sprintf( '%06d', random_int( 0, 999999 ) );
	$token = bin2hex( random_bytes( 32 ) );
	update_user_meta( $user->ID, meta_key(), array(
		'hash' => hash( 'sha256', $token ),
		'code_hash' => hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ),
		'code_attempts' => 0,
		'expires' => time() + 15 * MINUTE_IN_SECONDS,
		'password' => hash( 'sha256', $user->user_pass ),
		'email' => $user->user_email,
		'redirect' => wp_validate_redirect( $redirect, admin_url() ),
	) );
	return add_query_arg( array( 'action' => 'simple_magic_login', 'uid' => $user->ID, 'token' => $token ), site_url( 'wp-login.php', 'login' ) );
}

function validate_link( $id, $token ) {
	$user = get_user_by( 'id', $id );
	$data = get_user_meta( $id, meta_key(), true );
	if ( ! preg_match( '/^[a-f0-9]{64}$/D', $token ) || ! eligible( $user ) || ! is_array( $data ) || empty( $data['hash'] ) || $data['expires'] <= time()
		|| ! hash_equals( $data['hash'], hash( 'sha256', $token ) )
		|| ! hash_equals( $data['password'], hash( 'sha256', $user->user_pass ) ) || $data['email'] !== $user->user_email ) {
		return false;
	}
	return array( 'user' => $user, 'redirect' => $data['redirect'], 'record' => $data );
}

/** Compare and delete in one statement; metadata APIs select IDs before deleting. */
function consume_link( $id, $token ) {
	global $wpdb;
	$result = validate_link( $id, $token );
	if ( ! $result ) {
		return false;
	}
	return delete_record( $id, $result['record'] ) ? $result : false;
}

function delete_record( $id, $record ) {
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Atomic compare-and-delete prevents token reuse; user_meta cache is invalidated below.
	$deleted = $wpdb->query( $wpdb->prepare(
		"DELETE FROM $wpdb->usermeta WHERE user_id = %d AND meta_key = %s AND meta_value = %s",
		$id, meta_key(), maybe_serialize( $record )
	) );
	wp_cache_delete( $id, 'user_meta' );
	return (bool) $deleted;
}

function request_link( $email, $redirect ) {
	$ip_key = 'sml_ip_' . hash( 'sha256', sanitize_text_field( input( $_SERVER, 'REMOTE_ADDR' ) ) );
	$attempts = (int) get_site_transient( $ip_key );
	if ( $attempts >= 10 ) {
		log_event( 'request_throttled_ip' );
		return;
	}
	set_site_transient( $ip_key, $attempts + 1, 15 * MINUTE_IN_SECONDS );
	$user = get_user_by( 'email', $email );
	$allowed = eligible( $user, $reason );
	$notice = ! $allowed && 'two_factor_enabled' === $reason;
	if ( ! $allowed && ! $notice ) {
		log_event( 'request_blocked', array( 'reason' => $reason ) );
		return;
	}
	$key = 'sml_email_' . $user->ID;
	if ( get_site_transient( $key ) ) {
		log_event( 'request_throttled_user', array( 'user_id' => $user->ID ) );
		return;
	}
	set_site_transient( $key, 1, MINUTE_IN_SECONDS );
	$site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
	$record = null;
	if ( $notice ) {
		/* translators: %s: Site name. */
		$subject = sprintf( __( '[%s] Log in with your password', 'simple-magic-login' ), $site_name );
		$password_url = add_query_arg( 'password', '1', wp_login_url( wp_validate_redirect( $redirect, admin_url() ) ) );
		/* translators: 1: Site name, 2: Password login URL. */
		$message = sprintf( __( "You requested an email login for %1\$s. Your account has two-factor authentication enabled, so email login links and codes are unavailable.\n\nLog in with your password and complete two-factor authentication here:\n\n%2\$s\n\nIf you did not request this, you can ignore this email.", 'simple-magic-login' ), $site_name, $password_url );
	} else {
		$link = create_link( $user, $redirect, $code );
		$record = get_user_meta( $user->ID, meta_key(), true );
		/* translators: %s: Site name. */
		$subject = sprintf( __( '[%s] Your login link and code', 'simple-magic-login' ), $site_name );
		/* translators: 1: Single-use login URL, 2: Six-digit login code. */
		$message = sprintf( __( "Log in using this link:\n\n%1\$s\n\nOr enter this six-digit code on the login page with your email address: %2\$s\n\nThe link and code expire in 15 minutes. Using either invalidates both. If you did not request this, ignore this email.", 'simple-magic-login' ), $link, $code );
	}
	$mail_failure = function ( $error ) use ( $user ) {
		// Never log WP_Error data: it contains the full email and credentials.
		$message = preg_replace( array( '~https?://\\S+~i', '/[A-Z0-9._%+\\-]+@[A-Z0-9.\\-]+/i', '/\\b(?:[a-f0-9]{64}|[0-9]{6})\\b/i' ), '[redacted]', $error->get_error_message() );
		log_event( 'mail_transport_error', array( 'user_id' => $user->ID, 'error_codes' => $error->get_error_codes(), 'message' => substr( sanitize_text_field( $message ), 0, 500 ) ) );
	};
	add_action( 'wp_mail_failed', $mail_failure );
	try {
		$sent = wp_mail( $user->user_email, $subject, $message );
	} finally {
		remove_action( 'wp_mail_failed', $mail_failure );
	}
	log_event( $sent ? 'mail_accepted' : 'mail_failed', array( 'user_id' => $user->ID, 'mail_type' => $notice ? 'two_factor_notice' : 'login_credentials' ) );
	if ( ! $sent && $record ) {
		delete_record( $user->ID, $record );
	}

}

/** Reserve an attempt atomically so parallel requests cannot bypass the limit. */
function consume_code( $email, $code ) {
	global $wpdb;
	$user = get_user_by( 'email', $email );
	if ( ! eligible( $user ) ) return false;
	$id = $user->ID;
	$data = get_user_meta( $id, meta_key(), true );
	if ( ! is_array( $data ) || empty( $data['code_hash'] ) || $data['expires'] <= time()
		|| $data['code_attempts'] >= 5 || $data['email'] !== $user->user_email
		|| ! hash_equals( $data['password'], hash( 'sha256', $user->user_pass ) ) ) return false;
	$next = $data;
	++$next['code_attempts'];
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Atomic compare-and-swap reserves a code attempt; user_meta cache is invalidated below.
	$updated = $wpdb->query( $wpdb->prepare(
		"UPDATE $wpdb->usermeta SET meta_value = %s WHERE user_id = %d AND meta_key = %s AND meta_value = %s",
		maybe_serialize( $next ), $id, meta_key(), maybe_serialize( $data )
	) );
	wp_cache_delete( $id, 'user_meta' );
	if ( ! $updated ) return false;
	if ( ! preg_match( '/^[0-9]{6}$/D', $code ) || ! hash_equals( $data['code_hash'], hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ) ) ) {
		log_event( 'code_rejected', array( 'user_id' => $id, 'attempt' => $next['code_attempts'] ) );
		return false;
	}
	return delete_record( $id, $next ) ? array( 'user' => $user, 'redirect' => $data['redirect'] ) : false;
}

function code_form() {
	?>
	<details id="sml-code-login" style="width:320px;margin:24px auto" <?php
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display flag.
	echo isset( $_GET['code_error'] ) ? 'open' : '';
	?>>
		<summary><?php esc_html_e( 'Have a six-digit login code?', 'simple-magic-login' ); ?></summary>
		<form method="post" action="<?php echo esc_url( add_query_arg( 'action', 'simple_magic_code', site_url( 'wp-login.php', 'login_post' ) ) ); ?>">
			<p><label for="sml-code-email"><?php esc_html_e( 'Email Address', 'simple-magic-login' ); ?></label>
			<input class="input" type="email" name="email" id="sml-code-email" autocomplete="email" required></p>
			<p><label for="sml-code"><?php esc_html_e( 'Six-digit code', 'simple-magic-login' ); ?></label>
			<input class="input" type="text" name="code" id="sml-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></p>
			<?php wp_nonce_field( 'sml_code_login', '_sml_code_nonce', false ); ?>
			<p class="forgetmenot"><label><input type="checkbox" name="rememberme" value="forever"> <?php esc_html_e( 'Remember Me', 'simple-magic-login' ); ?></label></p>
			<p class="submit"><button class="button button-primary" type="submit"><?php esc_html_e( 'Log In', 'simple-magic-login' ); ?></button></p>
		</form>
	</details>
	<script>
	(function () {
		var codeForm = document.getElementById('sml-code-login');
		var login = document.getElementById('login');
		if (codeForm && login) {
			codeForm.style.width = 'auto';
			codeForm.style.margin = '24px 0';
			login.appendChild(codeForm);
		}
	})();
	</script>
	<?php
}

function redeem_code() {
	nocache_headers();
	$result = false;
	if ( isset( $_POST['_sml_code_nonce'] ) && wp_verify_nonce( input( $_POST, '_sml_code_nonce' ), 'sml_code_login' ) ) {
		$result = consume_code( sanitize_email( input( $_POST, 'email' ) ), trim( input( $_POST, 'code' ) ) );
	}
	if ( ! $result ) {
		log_event( 'code_login_failed' );
		wp_safe_redirect( add_query_arg( 'code_error', '1', site_url( 'wp-login.php', 'login' ) ) . '#sml-code-login' );
		exit;
	}
	log_event( 'code_login_succeeded', array( 'user_id' => $result['user']->ID ) );
	complete_login( $result );
}

function input( $source, $key ) {
	return isset( $source[ $key ] ) && is_string( $source[ $key ] ) ? wp_unslash( $source[ $key ] ) : '';
}

/** Handle email requests, then let wp-login.php render its own form. */
function login_page() {
	$is_post = ! empty( $_POST );
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only login status or password display flag.
	if ( isset( $_GET['password'] ) || ! empty( $_REQUEST['interim-login'] ) || ( $is_post && ! isset( $_POST['simple_magic_login'] ) ) ) {
		return;
	}
	if ( $is_post ) {
		$redirect = admin_url();
		$status = 'form_expired';
		if ( wp_verify_nonce( input( $_POST, '_sml_nonce' ), 'simple_magic_login_request' ) ) {
			$redirect = wp_validate_redirect( input( $_POST, 'redirect_to' ), admin_url() );
			$email = sanitize_email( input( $_POST, 'log' ) );
			if ( is_email( $email ) ) {
				request_link( $email, $redirect );
			} else {
				log_event( 'request_invalid_email' );
			}
			$status = 'sent';
		}
		if ( 'form_expired' === $status ) log_event( 'request_invalid_nonce' );
		wp_safe_redirect( add_query_arg( array( $status => '1', 'redirect_to' => $redirect ), site_url( 'wp-login.php', 'login' ) ) );
		exit;
	}
	add_filter( 'wp_login_errors', __NAMESPACE__ . '\\login_messages' );
	add_action( 'login_form', __NAMESPACE__ . '\\email_controls' );
	add_action( 'login_footer', __NAMESPACE__ . '\\adapt_login_form' );
	add_action( 'login_footer', __NAMESPACE__ . '\\code_form' );
}

function login_messages( $errors ) {
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only login status or password display flag.
	if ( isset( $_GET['code_error'] ) ) {
		$errors->add( 'sml_code', __( 'The code is invalid or expired. After five incorrect attempts, request a new email.', 'simple-magic-login' ) );
	}
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only login status or password display flag.
	if ( isset( $_GET['sent'] ) ) {
		$errors->add( 'sml_sent', __( 'If this email belongs to an account on this site, a login link has been sent. Please check your inbox.', 'simple-magic-login' ), 'message' );
	}
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only login status or password display flag.
	if ( isset( $_GET['invalid_link'] ) ) {
		$errors->add( 'sml_invalid', __( 'This login link is invalid or expired. Please request a new one.', 'simple-magic-login' ) );
	}
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only login status or password display flag.
	if ( isset( $_GET['form_expired'] ) ) {
		$errors->add( 'sml_expired', __( 'This form expired. Please try again.', 'simple-magic-login' ) );
	}
	return $errors;
}

function email_controls() {
	// Disabled until JavaScript adapts the native form; without JS, password login works.
	?>
	<input type="hidden" id="sml-email-mode" name="simple_magic_login" value="1" disabled>
	<?php wp_nonce_field( 'simple_magic_login_request', '_sml_nonce', false ); ?>
	<?php
}

function adapt_login_form() {
	?>
	<script>
	(function () {
		var form = document.getElementById('loginform');
		var marker = document.getElementById('sml-email-mode');
		if (!form || !marker) return;
		var login = form.querySelector('#user_login');
		var password = form.querySelector('#user_pass');
		var wrap = form.querySelector('.user-pass-wrap');
		var submit = form.querySelector('#wp-submit');
		var remember = form.querySelector('#rememberme');
		var rememberWrap = remember && remember.closest('.forgetmenot');
		var rememberDisplay = rememberWrap && rememberWrap.style.display;
		var label = form.querySelector('label[for="user_login"]');
		if (!login || !password || !wrap || !submit || !label) return;
		var original = { label: label.textContent, type: login.type, autocomplete: login.autocomplete, submit: submit.value, required: password.required, disabled: password.disabled, rememberDisabled: remember && remember.disabled };
		var toggle = document.createElement('a');
		toggle.href = <?php
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect passed to WordPress login URL generation and JSON encoded.
		echo wp_json_encode( add_query_arg( 'password', '1', wp_login_url( input( $_REQUEST, 'redirect_to' ) ) ) );
		?>;
		toggle.style.display = 'inline-flex';
		toggle.style.alignItems = 'center';
		toggle.style.gap = '4px';
		toggle.style.textDecoration = 'none';
		var icon = document.createElement('span');
		icon.className = 'dashicons dashicons-admin-network';
		icon.setAttribute('aria-hidden', 'true');
		icon.style.fontSize = '16px';
		icon.style.width = '16px';
		icon.style.height = '16px';
		var linkText = document.createElement('span');
		linkText.textContent = <?php echo wp_json_encode( __( 'Log in with password', 'simple-magic-login' ) ); ?>;
		linkText.style.textDecoration = 'underline';
		toggle.append(icon, linkText);
		toggle.setAttribute('aria-expanded', 'false');
		wrap.id = wrap.id || 'sml-password-fields';
		toggle.setAttribute('aria-controls', wrap.id);
		var nav = document.getElementById('nav');
		var lostPassword = nav && nav.querySelector('.wp-login-lost-password');
		var extraLink;
		if (lostPassword) {
			lostPassword.replaceWith(toggle);
		} else {
			if (!nav) {
				nav = document.createElement('p');
				nav.id = 'nav';
				form.insertAdjacentElement('afterend', nav);
			}
			extraLink = document.createElement('span');
			if (nav.textContent.trim()) extraLink.appendChild(document.createTextNode(' | '));
			extraLink.appendChild(toggle);
			nav.appendChild(extraLink);
		}
		marker.disabled = false;
		login.type = 'email';
		login.autocomplete = 'email';
		label.textContent = <?php echo wp_json_encode( __( 'Email Address', 'simple-magic-login' ) ); ?>;
		password.required = false;
		password.disabled = true;
		wrap.hidden = true;
		if (remember) remember.disabled = true;
		if (rememberWrap) {
			rememberWrap.hidden = true;
			rememberWrap.style.display = 'none';
		}
		submit.value = <?php echo wp_json_encode( __( 'Email me a login link', 'simple-magic-login' ) ); ?>;
		toggle.addEventListener('click', function (event) {
			event.preventDefault();
			marker.disabled = true;
			login.type = original.type;
			login.autocomplete = original.autocomplete;
			label.textContent = original.label;
			wrap.hidden = false;
			password.disabled = original.disabled;
			password.required = original.required;
			if (remember) remember.disabled = original.rememberDisabled;
			if (rememberWrap) {
				rememberWrap.hidden = false;
				rememberWrap.style.display = rememberDisplay;
			}
			submit.value = original.submit;
			toggle.setAttribute('aria-expanded', 'true');
			if (lostPassword) toggle.replaceWith(lostPassword);
			else extraLink.remove();
			password.focus();
		});
	})();
	</script>
	<?php
}

function redeem() {
	nocache_headers();
	header( 'Referrer-Policy: no-referrer' );
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only token validation; consumption requires the POST nonce below.
	$id = absint( input( $_GET, 'uid' ) );
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Token format is validated by validate_link; consumption requires the POST nonce below.
	$token = input( $_GET, 'token' );
	$is_post = isset( $_POST['_wpnonce'] );
	$result = validate_link( $id, $token );
	if ( $result && $is_post ) {
		$result = wp_verify_nonce( input( $_POST, '_wpnonce' ), 'sml_redeem_' . $token ) ? consume_link( $id, $token ) : false;
	}
	if ( ! $result ) {
		wp_safe_redirect( add_query_arg( 'invalid_link', '1', site_url( 'wp-login.php', 'login' ) ) );
		exit;
	}
	$user = $result['user'];
	if ( ! $is_post ) {
		login_header( __( 'Confirm login', 'simple-magic-login' ) );
		?>
		<form method="post" action="<?php echo esc_url( add_query_arg( array( 'action' => 'simple_magic_login', 'uid' => $id, 'token' => $token ), site_url( 'wp-login.php', 'login' ) ) ); ?>">
			<?php /* translators: %s: Account email address. */ ?>
			<p><?php echo esc_html( sprintf( __( 'Log in as %s?', 'simple-magic-login' ), $user->user_email ) ); ?></p>
			<?php wp_nonce_field( 'sml_redeem_' . $token ); ?>
			<p class="forgetmenot"><label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <?php esc_html_e( 'Remember Me', 'simple-magic-login' ); ?></label></p>
			<p class="submit"><button type="submit" class="button button-primary"><?php esc_html_e( 'Log In', 'simple-magic-login' ); ?></button></p>
		</form>
		<?php
		login_footer();
		exit;
	}
	complete_login( $result );
}

function complete_login( $result ) {
	$user = $result['user'];
	wp_set_current_user( $user->ID );
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Both callers verify their form nonce before completing login.
	wp_set_auth_cookie( $user->ID, 'forever' === input( $_POST, 'rememberme' ) );
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Notify the existing WordPress login hook.
	do_action( 'wp_login', $user->user_login, $user );
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Honor the existing WordPress redirect hook.
	$redirect = apply_filters( 'login_redirect', $result['redirect'], $result['redirect'], $user );
	wp_safe_redirect( $redirect );
	exit;
}

add_action( 'login_form_login', __NAMESPACE__ . '\\login_page' );
add_action( 'login_form_simple_magic_login', __NAMESPACE__ . '\\redeem' );

add_action( 'login_form_simple_magic_code', __NAMESPACE__ . '\\redeem_code' );
