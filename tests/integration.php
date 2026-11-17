<?php
// Run: wp --url=alex.kirk.at eval-file wp-content/plugins/simple-magic-login/tests/integration.php
require_once dirname( __DIR__ ) . '/simple-magic-login.php';
function sml_assert($ok, $message) { if (!$ok) { throw new Exception($message); } echo "PASS: $message\n"; }
add_filter('pre_wp_mail', '__return_true');
$id = wp_insert_user(array('user_login'=>'sml-test-'.wp_generate_password(10,false), 'user_email'=>'sml-test-'.wp_generate_password(10,false).'@example.invalid','user_pass'=>wp_generate_password(32),'role'=>'subscriber'));
if (is_wp_error($id)) { throw new Exception($id->get_error_message()); }
try {
 $user=get_user_by('id',$id);
 $link=SimpleMagicLogin\create_link($user,admin_url()); parse_str(wp_parse_url($link,PHP_URL_QUERY),$args);
 sml_assert(!SimpleMagicLogin\consume_link($id,'wrong'),'Reject wrong token');
 $blog=get_current_blog_id(); switch_to_blog(1); sml_assert(!SimpleMagicLogin\consume_link($id,$args['token']),'Reject token on another site'); restore_current_blog();
 sml_assert((bool)SimpleMagicLogin\validate_link($id,$args['token']),'GET validation accepts valid link');
 sml_assert((bool)SimpleMagicLogin\validate_link($id,$args['token']),'GET validation does not consume link');
 $deny=function(){return new WP_Error('blocked','Blocked');}; add_filter('wp_authenticate_user',$deny);
 sml_assert(!SimpleMagicLogin\consume_link($id,$args['token']),'Account restriction blocks redemption'); remove_filter('wp_authenticate_user',$deny);
 remove_user_from_blog($id,get_current_blog_id());
 sml_assert(!SimpleMagicLogin\consume_link($id,$args['token']),'Removed site member cannot redeem');
 add_user_to_blog(get_current_blog_id(),$id,'subscriber');
 sml_assert((bool)SimpleMagicLogin\consume_link($id,$args['token']),'Accept valid token');
 sml_assert(!SimpleMagicLogin\consume_link($id,$args['token']),'Reject reuse');
 $old=SimpleMagicLogin\create_link($user,admin_url()); parse_str(wp_parse_url($old,PHP_URL_QUERY),$old_args);
 $replacement=null;
 $replace=function($allowed)use($user,&$replacement){$replacement=SimpleMagicLogin\create_link($user,admin_url());return $allowed;};
 add_filter('simple_magic_login_allowed',$replace);
 sml_assert(!SimpleMagicLogin\consume_link($id,$old_args['token']),'Concurrent token replacement prevents old redemption');
 remove_filter('simple_magic_login_allowed',$replace);
 parse_str(wp_parse_url($replacement,PHP_URL_QUERY),$new_args);
 sml_assert((bool)SimpleMagicLogin\consume_link($id,$new_args['token']),'Concurrent replacement token survives');

 $link=SimpleMagicLogin\create_link($user,admin_url()); parse_str(wp_parse_url($link,PHP_URL_QUERY),$args);
 $data=get_user_meta($id,SimpleMagicLogin\meta_key(),true); $data['expires']=time()-1; update_user_meta($id,SimpleMagicLogin\meta_key(),$data);
 sml_assert(!SimpleMagicLogin\consume_link($id,$args['token']),'Reject expired token');
 $link=SimpleMagicLogin\create_link($user,admin_url()); parse_str(wp_parse_url($link,PHP_URL_QUERY),$args);
 wp_set_password(wp_generate_password(32),$id);
 sml_assert(!SimpleMagicLogin\consume_link($id,$args['token']),'Password change invalidates link');
 $link=SimpleMagicLogin\create_link(get_user_by('id',$id),admin_url()); parse_str(wp_parse_url($link,PHP_URL_QUERY),$args);
 wp_update_user(array('ID'=>$id,'user_email'=>'changed-'.$id.'@example.invalid'));
 sml_assert(!SimpleMagicLogin\consume_link($id,$args['token']),'Email change invalidates link');
 $user=get_user_by('id',$id);
 $link=SimpleMagicLogin\create_link($user,'https://attacker.invalid/'); parse_str(wp_parse_url($link,PHP_URL_QUERY),$args);
 sml_assert(SimpleMagicLogin\validate_link($id,$args['token'])['redirect']===admin_url(),'External redirect rejected');
 $mail=null; add_filter('pre_wp_mail',function($return,$atts)use(&$mail){$mail=$atts;return true;},10,2);
 SimpleMagicLogin\request_link($user->user_email,admin_url());
 sml_assert($mail && $mail['to']===$user->user_email && strpos($mail['message'],'action=simple_magic_login')!==false,'Generate email without sending');
 $mail=null; SimpleMagicLogin\request_link($user->user_email,admin_url()); sml_assert(!$mail,'Throttle repeat email');
} finally {
 delete_transient('sml_email_'.$id);
 delete_transient('sml_ip_'.hash('sha256',isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:''));
 require_once ABSPATH.'wp-admin/includes/ms.php'; wpmu_delete_user($id);
}
