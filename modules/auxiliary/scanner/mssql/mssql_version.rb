##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'MSSQL Server Version Enumeration',
      'Description' => %q{
        Enumerates the version of MSSQL servers.
      },
      'Author'      => 'Sion Dafydd <sion.dafydd[at]gmail.com>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(1433)
      ]
    )

    deregister_options('PASSWORD', 'TDSENCRYPTION', 'USERNAME', 'USE_WINDOWS_AUTHENT', 'DOMAIN')
  end

  def run_host(ip)
    begin
      disconnect if self.sock
      connect
      version = mssql_prelogin
      disconnect if self.sock
      unless version.nil?
        parse_version(version)
      end
    rescue ::Rex::ConnectionError, ::EOFError
      vprint_error("#{rhost}:#{rport} - Connection failed")
      return
    rescue ::Exception
      print_error("Error: #{$!}")
      return
    end
  end

  def parse_version(version)
    major = version[0].each_byte.first
    minor = version[1].each_byte.first
    build = (version[2].each_byte.first * 256) + version[3].each_byte.first
    subbuild = (version[4].each_byte.first * 256) + version[5].each_byte.first

    version_number = "#{major}.#{minor}.#{build}.#{subbuild}"

    if version_number =~ /^6\.0/
      branded_version = '6.0'
    elsif version_number =~ /^6\.5/
      branded_version = '6.5'
    elsif version_number =~ /^7\.0/
      branded_version = '7.0'
    elsif version_number =~ /^8\.0/
      branded_version = '2000'
    elsif version_number =~ /^9\.0/
      branded_version = '2005'
    elsif version_number =~ /^10\.0/
      branded_version = '2008'
    elsif version_number =~ /^10\.5/
      branded_version = '2008 R2'
    elsif version_number =~ /^11\.0/
      branded_version = '2012'
    elsif version_number =~ /^12\.0/
      branded_version = '2014'
    elsif version_number =~ /^13\.0/
      branded_version = '2016'
    else
      branded_version = ''
    end

    product_name = "Microsoft SQL Server #{branded_version}"
    product_name.rstrip!

    service_pack_lookup = {
        '6.5'     => { 201 => 'RTM', 213 => 'SP1', 240 => 'SP2', 258 => 'SP3', 281 => 'SP4', 415 => 'SP5',
                       416 => 'SP5a', 417 => 'SP5/SP5a' },
        '7.0'     => { 623 => 'RTM', 699 => 'SP1', 842 => 'SP2', 961 => 'SP3', 1063 => 'SP4' },
        '2000'    => { 384 => 'RTM', 532 => 'SP1', 534 => 'SP2', 760 => 'SP3', 766 => 'SP3a', 767 => 'SP3/SP3A',
                       2039 => 'SP4' },
        '2005'    => { 1399 => 'RTM', 2047 => 'SP1', 3042 => 'SP2', 4035 => 'SP3', 5000 => 'SP4' },
        '2008'    => { 1600 => 'RTM', 2531 => 'SP1', 4000 => 'SP2', 5500 => 'SP3', 6000 => 'SP4' },
        '2008 R2' => { 1600 => 'RTM', 2500 => 'SP1', 4000 => 'SP2', 6000 => 'SP3' },
        '2012'    => { 2100 => 'RTM', 3000 => 'SP1', 5058 => 'SP2', 6020 => 'SP3' },
        '2014'    => { 2000 => 'RTM', 4100 => 'SP1', 5000 => 'SP2' },
        '2016'    => { 1601 => 'RTM', 4001 => 'SP1' }
    }

    service_pack = nil
    patches = false

    if service_pack_lookup.has_key? branded_version
      service_pack_lookup[branded_version].each do | ver, sp |
        if build < ver and sp == 'RTM'
          service_pack = 'Pre-RTM'
          patches = false
          break
        elsif build == ver
          service_pack = sp
          patches = false
          break
        elsif build > ver
          service_pack = sp
          patches = true
        end
      end
    end

    if patches
      service_pack = service_pack + '+'
    end

    if service_pack.nil?
      info = "#{product_name} (#{version_number})"
    else
      info = "#{product_name} #{service_pack} (#{version_number})"
    end

    print_good(info)
    report_service(
        :host => rhost,
        :port => rport,
        :name => 'mssql',
        :info => info,
    )
  end

  def mssql_prelogin(enc_error=false)
    pkt_data_token = ''
    pkt_data = ''

    pkt_hdr =  [
        TYPE_PRE_LOGIN_MESSAGE, #type
        STATUS_END_OF_MESSAGE, #status
        0x0000, #length
        0x0000, # SPID
        0x00, # PacketID
        0x00 #Window
    ]

    version = [0x55010008, 0x0000].pack('Vv')
    encryption = ENCRYPT_NOT_SUP # off
    instoptdata = "MSSQLServer\0"

    threadid =   "\0\0" + Rex::Text.rand_text(2)

    idx = 21 # size of pkt_data_token
    pkt_data_token <<  [
        0x00, # Token 0 type Version
        idx, # VersionOffset
        version.length, # VersionLength

        0x01, # Token 1 type Encryption
        idx = idx + version.length, # EncryptionOffset
        0x01, # EncryptionLength

        0x02, # Token 2 type InstOpt
        idx = idx + 1, # InstOptOffset
        instoptdata.length, # InstOptLength

        0x03, # Token 3 type Threadid
        idx + instoptdata.length, # ThreadIdOffset
        0x04, # ThreadIdLength

        0xFF
    ].pack('CnnCnnCnnCnnC')

    pkt_data << pkt_data_token
    pkt_data << version
    pkt_data << encryption
    pkt_data << instoptdata
    pkt_data << threadid

    pkt_hdr[2] = pkt_data.length + 8

    pkt = pkt_hdr.pack('CCnnCC') + pkt_data

    resp = mssql_send_recv(pkt)

    idx = 0
    while resp && resp[0, 1] != "\xff" && resp.length > 5
      token = resp.slice!(0, 5)
      token = token.unpack('Cnn')
      idx -= 5
      if token[0] == 0x00 # We are looking for a Version option type
        idx += token[1]
        break
      end
    end

    if idx > 0
      version = resp[idx, 6]
    else
      version = nil
    end

    version
  end
end
