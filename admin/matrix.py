#!/usr/bin/env python3

# from openssl 3.0.0 util/libssl.num
lines = open('admin/libssl.num', 'r').readlines()

items = {}

for l in lines:
    l = l.strip()
    if not l or l[0] == '#':
        continue
    name, ord, ver, flags = l.split()
    exist, _, type, flags = flags.split(':')
    flags = set(flags.strip().split(','))
    flags.discard('')
    assert type == 'FUNCTION'
    if exist == 'EXIST':
        items[name] = flags

def flags(f):
    r = ['[^%s]' % x.lower() for x in sorted(f)]

    return ' '.join(r)

def curl_p(name):
    return ':white_check_mark:' if name in CURL else ''

def nginx_p(name):
    return ':white_check_mark:' if name in NGINX else ''

def httpd_p(name):
    return ':white_check_mark:' if name in HTTPD else ''

def impl_p(name):
    if name in impls:
        return ':white_check_mark:' if impls[name] else ':exclamation: [^stub]'
    return ''

def read_impls():
    next_line = False
    stub = False
    items = {}
    for line in open('src/entry.rs'):
        if 'entry! {' in line:
            next_line = True
            stub = False
            continue
        if 'entry_stub! {' in line:
            next_line = True
            stub = True
            continue

        if next_line and 'pub fn ' in line:
            parts = line.strip().replace('(', ' ').split()
            items[parts[2][1:]] = not stub

    return items

impls = read_impls()

# Combined requirements of curl 7.81.0-1ubuntu1.15, and curl 8.5.0
# extracted by running with LD_DEBUG=all
CURL = set("""
BIO_f_ssl
OPENSSL_init_ssl
SSL_alert_desc_string_long
SSL_CIPHER_get_name
SSL_connect
SSL_ctrl
SSL_CTX_add_client_CA
SSL_CTX_check_private_key
SSL_CTX_ctrl
SSL_CTX_free
SSL_CTX_get_cert_store
SSL_CTX_load_verify_dir
SSL_CTX_load_verify_file
SSL_CTX_new
SSL_CTX_sess_set_new_cb
SSL_CTX_set_alpn_protos
SSL_CTX_set_cert_store
SSL_CTX_set_cipher_list
SSL_CTX_set_ciphersuites
SSL_CTX_set_default_passwd_cb
SSL_CTX_set_default_passwd_cb_userdata
SSL_CTX_set_keylog_callback
SSL_CTX_set_msg_callback
SSL_CTX_set_next_proto_select_cb
SSL_CTX_set_options
SSL_CTX_set_post_handshake_auth
SSL_CTX_set_srp_password
SSL_CTX_set_srp_username
SSL_CTX_set_verify
SSL_CTX_use_certificate
SSL_CTX_use_certificate_chain_file
SSL_CTX_use_certificate_file
SSL_CTX_use_certificate
SSL_CTX_use_PrivateKey_file
SSL_CTX_use_PrivateKey
SSL_CTX_use_PrivateKey_file
SSL_free
SSL_get0_alpn_selected
SSL_get0_verified_chain
SSL_get1_peer_certificate
SSL_get_certificate
SSL_get_current_cipher
SSL_get_error
SSL_get_ex_data
SSL_get_peer_cert_chain
SSL_get_peer_signature_type_nid
SSL_get_privatekey
SSL_get_shutdown
SSL_get_verify_result
SSL_get_version
SSL_new
SSL_pending
SSL_read
SSL_SESSION_free
SSL_set_bio
SSL_set0_rbio
SSL_set0_wbio
SSL_set_connect_state
SSL_set_ex_data
SSL_set_fd
SSL_set_session
SSL_shutdown
SSL_write
TLS_client_method
""".split())

# Combined requirements of nginx 1.18.0-6ubuntu14.4, and nginx 1.24.0,
# and fedora nginx 1.26.1-1.fc40.  extracted by running with LD_DEBUG=all
NGINX = set("""
d2i_SSL_SESSION
i2d_SSL_SESSION
OPENSSL_init_ssl
SSL_CIPHER_description
SSL_CIPHER_find
SSL_CIPHER_get_id
SSL_CIPHER_get_name
SSL_clear_options
SSL_CONF_cmd
SSL_CONF_cmd_value_type
SSL_CONF_CTX_finish
SSL_CONF_CTX_free
SSL_CONF_CTX_new
SSL_CONF_CTX_set_flags
SSL_CONF_CTX_set_ssl_ctx
SSL_ctrl
SSL_CTX_add_custom_ext
SSL_CTX_callback_ctrl
SSL_CTX_clear_options
SSL_CTX_ctrl
SSL_CTX_free
SSL_CTX_get_cert_store
SSL_CTX_get_client_CA_list
SSL_CTX_get_ex_data
SSL_CTX_get_max_early_data
SSL_CTX_get_options
SSL_CTX_get_timeout
SSL_CTX_get_verify_callback
SSL_CTX_get_verify_depth
SSL_CTX_get_verify_mode
SSL_CTX_has_client_custom_ext
SSL_CTX_load_verify_locations
SSL_CTX_new
SSL_CTX_remove_session
SSL_CTX_sess_set_get_cb
SSL_CTX_sess_set_new_cb
SSL_CTX_sess_set_remove_cb
SSL_CTX_set_alpn_protos
SSL_CTX_set_alpn_select_cb
SSL_CTX_set_cert_cb
SSL_CTX_set_cipher_list
SSL_CTX_set_client_CA_list
SSL_CTX_set_ex_data
SSL_CTX_set_info_callback
SSL_CTX_set_keylog_callback
SSL_CTX_set_max_early_data
SSL_CTX_set_next_protos_advertised_cb
SSL_CTX_set_options
SSL_CTX_set_session_id_context
SSL_CTX_set_timeout
SSL_CTX_set_verify_depth
SSL_CTX_set_verify
SSL_CTX_set_verify_depth
SSL_CTX_use_certificate
SSL_CTX_use_PrivateKey
SSL_do_handshake
SSL_free
SSL_get0_alpn_selected
SSL_get0_next_proto_negotiated
SSL_get0_verified_chain
SSL_get1_peer_certificate
SSL_get1_session
SSL_get_certificate
SSL_get_current_cipher
SSL_get_error
SSL_get_ex_data
SSL_get_ex_data_X509_STORE_CTX_idx
SSL_get_options
SSL_get_peer_cert_chain
SSL_get_rbio
SSL_get_servername
SSL_get_session
SSL_get_shutdown
SSL_get_SSL_CTX
SSL_get_verify_result
SSL_get_version
SSL_get_wbio
SSL_in_init
SSL_is_init_finished
SSL_load_client_CA_file
SSL_new
SSL_read_early_data
SSL_read
SSL_read_early_data
SSL_select_next_proto
SSL_sendfile
SSL_SESSION_free
SSL_SESSION_get_id
SSL_SESSION_get_time
SSL_SESSION_get_timeout
SSL_session_reused
SSL_SESSION_set1_id_context
SSL_SESSION_set_time
SSL_SESSION_set_timeout
SSL_SESSION_up_ref
SSL_set_accept_state
SSL_set_bio
SSL_set_connect_state
SSL_set_ex_data
SSL_set_fd
SSL_set_max_early_data
SSL_set_msg_callback
SSL_set_options
SSL_set_quiet_shutdown
SSL_set_session
SSL_set_shutdown
SSL_set_SSL_CTX
SSL_set_verify_depth
SSL_set_verify
SSL_set_verify_depth
SSL_shutdown
SSL_use_certificate
SSL_use_PrivateKey
SSL_version
SSL_write_early_data
SSL_write
SSL_write_early_data
TLS_method
""".split())

# extracted from upstream httpd trunk @df01c0 w/ mod_ssl
# by running with LD_DEBUG=all
HTTPD = set("""
d2i_SSL_SESSION
i2d_SSL_SESSION
OPENSSL_atexit
OPENSSL_cleanse
OPENSSL_DIR_end
OPENSSL_DIR_read
OPENSSL_init_crypto
OPENSSL_init_ssl
OPENSSL_LH_delete
OPENSSL_LH_free
OPENSSL_LH_get_down_load
OPENSSL_LH_insert
OPENSSL_LH_new
OPENSSL_LH_num_items
OPENSSL_LH_retrieve
OPENSSL_LH_set_down_load
OPENSSL_sk_delete
OPENSSL_sk_dup
OPENSSL_sk_find
OPENSSL_sk_free
OPENSSL_sk_insert
OPENSSL_sk_new
OPENSSL_sk_new_null
OPENSSL_sk_new_reserve
OPENSSL_sk_num
OPENSSL_sk_pop
OPENSSL_sk_pop_free
OPENSSL_sk_push
OPENSSL_sk_set_cmp_func
OPENSSL_sk_shift
OPENSSL_sk_sort
OPENSSL_sk_unshift
OPENSSL_sk_value
OPENSSL_strcasecmp
OPENSSL_strncasecmp
OPENSSL_strnlen
OpenSSL_version
OpenSSL_version_num
SSL_accept
SSL_add_file_cert_subjects_to_stack
SSL_alert_desc_string_long
SSL_alert_type_string_long
SSL_check_private_key
SSL_CIPHER_get_bits
SSL_CIPHER_get_name
SSL_clear_options
SSL_client_hello_get0_ext
SSL_COMP_get_compression_methods
SSL_CONF_cmd
SSL_CONF_cmd_value_type
SSL_CONF_CTX_finish
SSL_CONF_CTX_free
SSL_CONF_CTX_new
SSL_CONF_CTX_set_flags
SSL_CONF_CTX_set_ssl_ctx
SSL_connect
SSL_ctrl
SSL_CTX_callback_ctrl
SSL_CTX_check_private_key
SSL_CTX_ctrl
SSL_CTX_free
SSL_CTX_get0_certificate
SSL_CTX_get_cert_store
SSL_CTX_get_client_CA_list
SSL_CTX_get_ex_data
SSL_CTX_get_options
SSL_CTX_get_verify_callback
SSL_CTX_get_verify_mode
SSL_CTX_load_verify_dir
SSL_CTX_load_verify_file
SSL_CTX_new
SSL_CTX_sess_set_get_cb
SSL_CTX_sess_set_new_cb
SSL_CTX_sess_set_remove_cb
SSL_CTX_set0_tmp_dh_pkey
SSL_CTX_set_alpn_select_cb
SSL_CTX_set_cipher_list
SSL_CTX_set_ciphersuites
SSL_CTX_set_client_CA_list
SSL_CTX_set_client_cert_cb
SSL_CTX_set_client_hello_cb
SSL_CTX_set_default_passwd_cb
SSL_CTX_set_ex_data
SSL_CTX_set_info_callback
SSL_CTX_set_keylog_callback
SSL_CTX_set_options
SSL_CTX_set_post_handshake_auth
SSL_CTX_set_srp_cb_arg
SSL_CTX_set_srp_username_callback
SSL_CTX_set_timeout
SSL_CTX_set_tlsext_ticket_key_evp_cb
SSL_CTX_set_verify
SSL_CTX_use_certificate
SSL_CTX_use_certificate_chain_file
SSL_CTX_use_certificate_file
SSL_CTX_use_PrivateKey
SSL_CTX_use_PrivateKey_file
SSL_do_handshake
SSL_free
SSL_get0_alpn_selected
SSL_get1_peer_certificate
SSL_get_certificate
SSL_get_ciphers
SSL_get_client_CA_list
SSL_get_current_cipher
SSL_get_error
SSL_get_ex_data
SSL_get_ex_data_X509_STORE_CTX_idx
SSL_get_finished
SSL_get_peer_cert_chain
SSL_get_peer_finished
SSL_get_rbio
SSL_get_servername
SSL_get_session
SSL_get_shared_ciphers
SSL_get_shutdown
SSL_get_srp_userinfo
SSL_get_srp_username
SSL_get_SSL_CTX
SSL_get_verify_depth
SSL_get_verify_mode
SSL_get_verify_result
SSL_get_version
SSL_get_wbio
SSL_in_init
SSL_is_init_finished
SSL_is_server
SSL_new
SSL_peek
SSL_read
SSL_renegotiate
SSL_SESSION_get_compress_id
SSL_SESSION_get_id
SSL_SESSION_get_time
SSL_session_reused
SSL_SESSION_set_timeout
SSL_set_accept_state
SSL_set_alpn_protos
SSL_set_bio
SSL_set_cipher_list
SSL_set_ex_data
SSL_set_options
SSL_set_session_id_context
SSL_set_shutdown
SSL_set_srp_server_param
SSL_set_SSL_CTX
SSL_set_verify
SSL_set_verify_result
SSL_shutdown
SSL_state_string_long
SSL_use_certificate
SSL_use_PrivateKey
SSL_verify_client_post_handshake
SSL_version
SSL_write
""".split())

print('| Symbol | curl[^curl] | nginx[^nginx] | httpd[^httpd] | implemented? |')
print('|---|---|---|---|---|')
for i in sorted(items.keys()):
    print('| `' + i + '` ' + flags(items[i]) + ' | ' + curl_p(i) + ' | ' + nginx_p(i) + ' | ' + httpd_p(i) + ' | ' + impl_p(i) + ' |')

print("""
[^stub]: symbol exists, but just returns an error.
[^deprecatedin_1_1_0]: deprecated in openssl 1.1.0
[^deprecatedin_3_0]: deprecated in openssl 3.0
[^stdio]: depends on C stdio `FILE*`
[^ct]: certificate transparency-specific (NYI in rustls)
[^nextprotoneg]: next protocol negotiation (NPN) feature -- non-standard precursor to ALPN
[^srp]: SRP-specific
[^srtp]: SRTP-specific
[^psk]: pre-shared-key-specific
[^sock]: specific to platforms with file descriptors
[^unit_test]: access to openssl internals for unit testing
[^ssl_trace]: protocol tracing API
[^dtls1_2_method]: DTLS 1.2-specific
[^dtls1_method]: DTLS 1.0-specific
[^dh]: Diffie-Hellman-specific
[^ssl3_method]: SSL 3.0-specific
[^tls1_method]: TLS 1.0-specific
[^tls1_1_method]: TLS 1.1-specific
[^tls1_2_method]: TLS 1.2-specific
[^engine]: openssl ENGINE-specific
[^curl]: curl 7.81.0-1ubuntu1.16 (ubuntu 22.04)
[^nginx]: nginx 1.18.0-6ubuntu14.4 (ubuntu 22.04)
[^httpd]: apache httpd trunk
""")