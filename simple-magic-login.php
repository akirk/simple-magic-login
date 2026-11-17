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

function eligible( $user ) {
	if ( ! $user instanceof \WP_User || ( is_multisite() && ( ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) || $user->spam || $user->deleted ) ) ) {
		return false;
	}
	// Email links cannot complete the Two Factor plugin's challenge flow.
	if ( class_exists( '\Two_Factor_Core' ) && \Two_Factor_Core::is_user_using_two_factor( $user->ID ) ) {
		return false;
	}
	$checked = apply_filters( 'wp_authenticate_user', $user, '' );
	return $checked instanceof \WP_User && $checked->ID === $user->ID
		&& (bool) apply_filters( 'simple_magic_login_allowed', true, $user );
}

function meta_key() {
	return '_simple_magic_login_' . get_current_blog_id();
}

function create_link( $user, $redirect ) {
	$token = bin2hex( random_bytes( 32 ) );
	update_user_meta( $user->ID, meta_key(), array(
		'hash' => hash( 'sha256', $token ),
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
	$deleted = $wpdb->query( $wpdb->prepare(
		"DELETE FROM $wpdb->usermeta WHERE user_id = %d AND meta_key = %s AND meta_value = %s",
		$id, meta_key(), maybe_serialize( $result['record'] )
	) );
	wp_cache_delete( $id, 'user_meta' );
	return $deleted ? $result : false;
}

function request_link( $email, $redirect ) {
	$ip_key = 'sml_ip_' . hash( 'sha256', isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '' );
	$attempts = (int) get_transient( $ip_key );
	if ( $attempts >= 10 ) {
		return;
	}
	set_transient( $ip_key, $attempts + 1, 15 * MINUTE_IN_SECONDS );
	$user = get_user_by( 'email', $email );
	if ( ! eligible( $user ) ) {
		return;
	}
	$key = 'sml_email_' . $user->ID;
	if ( get_transient( $key ) ) {
		return;
	}
	set_transient( $key, 1, MINUTE_IN_SECONDS );
	$link = create_link( $user, $redirect );
	$record = get_user_meta( $user->ID, meta_key(), true );
	$sent = wp_mail(
		$user->user_email,
		sprintf( __( '[%s] Your login link', 'simple-magic-login' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) ),
		sprintf( __( "Log in using this link:\n\n%s\n\nThis link expires in 15 minutes and can be used once. If you did not request it, you can ignore this email.", 'simple-magic-login' ), $link )
	);
	if ( ! $sent ) {
		delete_user_meta( $user->ID, meta_key(), $record );
	}
}

function input( $source, $key ) {
	return isset( $source[ $key ] ) && is_string( $source[ $key ] ) ? wp_unslash( $source[ $key ] ) : '';
}

/** Handle email requests, then let wp-login.php render its own form. */
function login_page() {
	$is_post = 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? 'GET' );
	if ( isset( $_GET['password'] ) || ! empty( $_REQUEST['interim-login'] ) || ( $is_post && ! isset( $_POST['simple_magic_login'] ) ) ) {
		return;
	}
	if ( $is_post ) {
		$redirect = wp_validate_redirect( input( $_POST, 'redirect_to' ), admin_url() );
		$status = 'form_expired';
		if ( wp_verify_nonce( input( $_POST, '_sml_nonce' ), 'simple_magic_login_request' ) ) {
			$email = sanitize_email( input( $_POST, 'log' ) );
			if ( is_email( $email ) ) {
				request_link( $email, $redirect );
			}
			$status = 'sent';
		}
		wp_safe_redirect( add_query_arg( array( $status => '1', 'redirect_to' => $redirect ), site_url( 'wp-login.php', 'login' ) ) );
		exit;
	}
	add_filter( 'wp_login_errors', __NAMESPACE__ . '\\login_messages' );
	add_action( 'login_form', __NAMESPACE__ . '\\email_controls' );
	add_action( 'login_footer', __NAMESPACE__ . '\\adapt_login_form' );
}

function login_messages( $errors ) {
	if ( isset( $_GET['sent'] ) ) {
		$errors->add( 'sml_sent', __( 'If this email belongs to an account on this site, a login link has been sent. Please check your inbox.', 'simple-magic-login' ), 'message' );
	}
	if ( isset( $_GET['invalid_link'] ) ) {
		$errors->add( 'sml_invalid', __( 'This login link is invalid or expired. Please request a new one.', 'simple-magic-login' ) );
	}
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
		toggle.href = <?php echo wp_json_encode( add_query_arg( 'password', '1', wp_login_url( input( $_REQUEST, 'redirect_to' ) ) ) ); ?>;
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
	$id = absint( input( $_GET, 'uid' ) );
	$token = input( $_GET, 'token' );
	$is_post = 'POST' === $_SERVER['REQUEST_METHOD'];
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
			<p><?php echo esc_html( sprintf( __( 'Log in as %s?', 'simple-magic-login' ), $user->user_email ) ); ?></p>
			<?php wp_nonce_field( 'sml_redeem_' . $token ); ?>
			<p class="forgetmenot"><label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <?php esc_html_e( 'Remember Me', 'simple-magic-login' ); ?></label></p>
			<p class="submit"><button type="submit" class="button button-primary"><?php esc_html_e( 'Log In', 'simple-magic-login' ); ?></button></p>
		</form>
		<?php
		login_footer();
		exit;
	}
	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, 'forever' === input( $_POST, 'rememberme' ) );
	do_action( 'wp_login', $user->user_login, $user );
	$redirect = apply_filters( 'login_redirect', $result['redirect'], $result['redirect'], $user );
	wp_safe_redirect( $redirect );
	exit;
}

add_action( 'login_form_login', __NAMESPACE__ . '\\login_page' );
add_action( 'login_form_simple_magic_login', __NAMESPACE__ . '\\redeem' );
