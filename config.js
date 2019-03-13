module.exports = {
  company_name: 'Fleet-America',
  binding_port: 3000,
  name: 'Pinpoint_Membership',
  jwt_algorithm: 'HS512',
  crypto_algorithm: 'aes-256-ctr',
  mongodb_connection: 'mongodb://data_writer:10072004@pinpoint.ddns.net/Pinpoint_Membership',
  email_server_name: 'hostgator.com',
  email_host: 'gator3029.hostgator.com',
  smtp_port: 465,
  email_username: 'ghassan@fleet-america.com',
  email_password: '10072004',
  email_from: 'Fleet-America <support@fleet-america.com>',
  email_reset_subject: 'Fleet-America account password reset',
  username_is_email: true,
  password_reset_page: 'http://pin_point.com/pwdreset/',
  crypt_pwd: 'Pass@123456',
  reset_pin_age: 24 //hour-s
	
};
