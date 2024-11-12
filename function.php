
// registration using api

add_action('rest_api_init', 'custom_user_registration');

function custom_user_registration()
{
    register_rest_route('wp/v2', '/users/register', array(
        'methods' => 'POST',
        'callback' => 'custom_user_registration_callback',
        'permission_callback' => '__return_true', // Allow public access
    ));
}

function custom_user_registration_callback($request)
{
    $username = sanitize_text_field($request->get_param('username'));
    $email = sanitize_email($request->get_param('email'));
    $password = sanitize_text_field($request->get_param('password'));

    if (empty($username) || empty($email) || empty($password)) {
        return new WP_Error('missing_fields', 'Missing required fields', array('status' => 405));
    }

    if (username_exists($username) || email_exists($email)) {
        return new WP_Error('user_exists', 'User already exists', array('status' => 422));
    }

    $user_id = wp_create_user($username, $password, $email);

    if (is_wp_error($user_id)) {
        return new WP_Error('user_creation_failed', 'User registration failed', array('status' => 400));
    }

    return array('user_id' => $user_id, 'message' => 'User registered successfully');
}
// Register custom REST API endpoints
function custom_register_rest_endpoints()
{
    register_rest_route('custom/v1', '/initiate-otp', array(
        'methods' => 'POST',
        'callback' => 'custom_initiate_otp',
        // 'permission_callback' => function () {
        //     return current_user_can('edit_users'); // Adjust permissions as needed
        // },
    ));

    register_rest_route('custom/v1', '/verify-otp', array(
        'methods' => 'POST',
        'callback' => 'custom_verify_otp',
    ));

    register_rest_route('custom/v1', '/update-password', array(
        'methods' => 'POST',
        'callback' => 'custom_update_password',
    ));
}

add_action('rest_api_init', 'custom_register_rest_endpoints');


// Callback function for initiating OTP
function custom_initiate_otp($request)
{
    $parameters = $request->get_json_params();

    $username_or_email = isset($parameters['username_or_email']) ? sanitize_text_field($parameters['username_or_email']) : '';

    // Get user ID by username or email
    $user = get_user_by('login', $username_or_email);
    if (!$user) {
        $user = get_user_by('email', $username_or_email);
    }

    if ($user) {
        $user_id = $user->ID;

        $otp = mt_rand(100000, 999999);

        update_user_meta($user_id, 'otp_for_update', $otp);
        update_user_meta($user_id, 'otp_expiry_time', time() + 300); // OTP valid for 5 minutes

        $to = $user->user_email;
        $subject = 'OTP for Username/Password Update';
        $message = 'Your OTP for username/password update is: ' . $otp;
        $headers = array('Content-Type: text/html; charset=UTF-8');

        $sent = wp_mail($to, $subject, $message, $headers);

        if ($sent) {
            return new WP_REST_Response('OTP sent successfully', 200);
        } else {
            return new WP_REST_Response('Failed to send OTP', 500);
        }
    } else {
        return new WP_REST_Response('User not found', 404);
    }
}


// Callback function for verifying OTP and updating username/password
function custom_verify_otp($request)
{
    $parameters = $request->get_json_params();

    $username_or_email = isset($parameters['username_or_email']) ? sanitize_text_field($parameters['username_or_email']) : '';
    $submitted_otp = isset($parameters['otp']) ? sanitize_text_field($parameters['otp']) : '';

    $user = get_user_by('login', $username_or_email);
    if (!$user) {
        $user = get_user_by('email', $username_or_email);
    }

    if ($user) {
        $user_id = $user->ID;

        $stored_otp = get_user_meta($user_id, 'otp_for_update', true);
        $otp_expiry_time = get_user_meta($user_id, 'otp_expiry_time', true);

        if ($stored_otp == $submitted_otp && time() < $otp_expiry_time) {

            $tem_auth_token = bin2hex(openssl_random_pseudo_bytes(16 / 2));

            update_user_meta($user_id, 'temp_auth_token_for_update_pass', $tem_auth_token);
            update_user_meta($user_id, 'temp_auth_token_expiry_time', time() + 600); // OTP valid for 5 minutes

            delete_user_meta($user_id, 'otp_for_update');
            delete_user_meta($user_id, 'otp_expiry_time');

            return new WP_REST_Response(array('temp_auth_token' => $tem_auth_token, 'message' => 'Temporary Auth token has created.', 'status' => 200));
        } else {
            return new WP_Error('cant-update', __('OTP expired or invaild.', 'text-domain'), array('status' => 400));
        }
    } else {

        return new WP_Error('cant-update', __('User not found', 'text-domain'), array('status' => 404));
    }
}


// Callback function for updating password
function custom_update_password($request)
{
    $parameters = $request->get_json_params();

    $username_or_email = isset($parameters['username_or_email']) ? sanitize_text_field($parameters['username_or_email']) : '';
    $submited_temp_auth_token = isset($parameters['temp_auth_token']) ? sanitize_text_field($parameters['temp_auth_token']) : '';
    $new_password = isset($parameters['new_password']) ? $parameters['new_password'] : '';

    $user = get_user_by('login', $username_or_email);
    if (!$user) {
        $user = get_user_by('email', $username_or_email);
    }

    if ($user) {
        $user_id = $user->ID;

        $stored_temp_auth_token = get_user_meta($user_id, 'temp_auth_token_for_update_pass', true);
        $temp_auth_token_expiry_time = get_user_meta($user_id, 'temp_auth_token_expiry_time', true);

        if ($stored_temp_auth_token == $submited_temp_auth_token && time() < $temp_auth_token_expiry_time) {

            wp_set_password($new_password, $user_id);

            delete_user_meta($user_id, 'temp_auth_token_for_update_pass');
            delete_user_meta($user_id, 'temp_auth_token_expiry_time');

            return new WP_REST_Response(array('message' => 'The password has been updated. .', 'status' => 200));
        } else {

            return new WP_Error('cant-update', __('Unable to update, Please try again', 'text-domain'), array('status' => 400));
        }
    } else {
        return new WP_Error('cant-update', __('Unable to update, Please try again', 'text-domain'), array('status' => 404));
    }
}
