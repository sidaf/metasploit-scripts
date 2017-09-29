##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp

  def initialize
    super(
        'Name'        => 'IKEv1 Aggressive Mode Scanner',
        'Description' => %q{
        Blah.
      },
        'Author'      => 'Sion Dafydd <sion.dafydd[at]gmail.com>',
        'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(500)
      ], self.class
    )

    register_advanced_options(
      [
        Opt::CPORT(500)
      ], self.class
    )

    deregister_options('RHOST', 'THREADS')
  end

  def run_host(ip)
    # Note, in aggressive mode, the GROUP_DESCRIPTION must be the same across all transforms and the 'diffie_helman' variable
    transforms = [
      [ ENC_METHOD['3DES'], HASH_ALGORITHM['SHA1'], AUTH_TYPE['PSK'], GROUP_DESCRIPTION['1024'], '800b0001', '000c000400007080'],
      [ ENC_METHOD['3DES'], HASH_ALGORITHM['MD5'],  AUTH_TYPE['PSK'], GROUP_DESCRIPTION['1024'], '800b0001', '000c000400007080'],
      [ ENC_METHOD['DES'],  HASH_ALGORITHM['SHA1'], AUTH_TYPE['PSK'], GROUP_DESCRIPTION['1024'], '800b0001', '000c000400007080'],
      [ ENC_METHOD['DES'],  HASH_ALGORITHM['MD5'],  AUTH_TYPE['PSK'], GROUP_DESCRIPTION['1024'], '800b0001', '000c000400007080']
    ]
    aggressive = true
    diffie_helman = 2
    identifier = 'blah'

    debug = true

    begin
      connect_udp unless debug

      isakmp_pkt = generate_packet(rport, transforms, aggressive, diffie_helman, identifier, debug)

      return if debug

      udp_socket.write(isakmp_pkt)
      response = udp_socket.get(3)

      return unless response.length > 36 # ISAKMP + 36 -> Notification Data...

      # do stuff with response
      #parse_packet()

    rescue => e
      print_error(e)
    ensure
      disconnect_udp unless debug
    end
  end

  def generate_packet(port, transforms, aggressive, dh, id, debug)

    # OK, we are going to create this packet backwards so that the lengths can be calculated and inserted

    # Key Exchange, Nonce, and Identification Payloads (Aggressive Mode Only)
    if aggressive
      aggressive_payload = generate_aggressive(port, id, dh)
    else
      aggressive_payload = [''].pack('H*')
    end

    # Transform Payloads
    transforms_payload = [''].pack('H*')
    transforms.each_with_index do | transform, index |
      number = index + 1
      transforms_payload += generate_transform(transform[0], transform[1], transform[2], transform[3],
                                               transform[4], transform[5], number, (number == transforms.size))
    end

    # Proposal Payload
    proposal_payload  = ['00'].pack('H*')                               # Proposal
    proposal_payload += ['00'].pack('H*')                               # Critical Bit
    proposal_payload += [sprintf('%04x', 8 + transforms_payload.size)].pack('H*') # Payload Length (152)
    proposal_payload += ['01'].pack('H*')                               # Proposal number
    proposal_payload += ['01'].pack('H*')                               # Protocol ID: ISAKMP (1)
    proposal_payload += ['00'].pack('H*')                               # SPI size: 0
    proposal_payload += [sprintf('%02x', transforms.count)].pack('H*')  # Number of Proposal Transforms

    # Security Association (SA) Payload
    if aggressive
      sa_payload = ['04'].pack('H*')                                    # Next Payload (Key Exchange)
    else
      sa_payload = ['00'].pack('H*')                                    # Next Payload (None)
    end
    sa_payload += ['00'].pack('H*')                                     # Critical Bit: Not Critical
    sa_payload += [sprintf('%04x', 12 + proposal_payload.size + transforms_payload.size)].pack('H*') # Payload Length (164)
    sa_payload += ['00000001'].pack('H*')                               # Domain of Interpretation (DOI): IPSEC (1)
    sa_payload += ['00000001'].pack('H*')                               # Situation: Identity Only (1)

    # Header Payload
    header_payload  = ['0102030405060708'].pack('H*')                   # Initiator SPI
    header_payload += ['0000000000000000'].pack('H*')                   # Responder SPI
    header_payload += ['01'].pack('H*')                                 # Next Payload (Security Association)
    header_payload += ['10'].pack('H*')                                 # Version: 1.0
    if aggressive
      header_payload += ['04'].pack('H*')                               # Exchange type: AGGRESSIVE (04)
    else
      header_payload += ['02'].pack('H*')                               # Exchange type: MAIN (02)
    end
    header_payload += ['00'].pack('H*')                                 # Flags:
    header_payload += ['00000000'].pack('H*')                           # Message ID
    header_payload += [sprintf('%08x', 28 + proposal_payload.size + transforms_payload.size + aggressive_payload.size)].pack('H*') # Payload Length (360)

    print_line if debug
    print_line(Rex::Text.to_hex_dump(payload)) if debug

    # Assemble packet components in correct order and return
    return header_payload + sa_payload + proposal_payload + transforms_payload + aggressive_payload
  end

  def generate_transform(encryption, hash, authentication, group, life_type, life_duration, number, last)
    if encryption.is_a? Array
      # Handle special case for AES
      enc = encryption[0]
      trans_length = '0028'
      key_length = encryption[1]
    else
      enc = encryption
      trans_length = '0024'
      key_length = nil
    end

    if last
      payload  = ['00'].pack('H*')                  # Next Payload (None)
    else
      payload += ['03'].pack('H*')                  # Next Payload (Transform)
    end
    payload += ['00'].pack('H*')                    # Critical Bit
    payload += [trans_length].pack('H*')            # Payload Length
    payload += [sprintf('%02x', number)].pack('H*') # Transform number
    payload += ['01'].pack('H*')                    # Transform ID: KEY_IKE (1)
    payload += ['0000'].pack('H*')                  #
    payload += [enc].pack('H*')                     # Encryption-Algorithm
    payload += [hash].pack('H*')                    # Hash-Algorithm
    payload += [authentication].pack('H*')          # Authentication-Method
    payload += [group].pack('H*')                   # Group-Description
    if key_length
      payload += [key_length].pack('H*')            # AES Key Length
    end
    payload += [life_type].pack('H*')               # Life-Type
    payload += [life_duration].pack('H*')           # Life-Duration

    return payload
  end

  def generate_aggressive(port, id, dh)

    # Get length of key data based on diffie
    if dh == 1 then
      key_length = 96
    elsif dh == 2 then
      key_length = 128
    elsif dh == 5 then
      key_length = 192
    elsif dh == 14 then
      raise RuntimeError, 'TODO'
    else
      raise RuntimeError, 'Unknown Diffie Helman Value'
    end

    # Key Exchange Payload
    payload  = ['0a'].pack('H*')                            # Next Payload (Nonce)
    payload += ['00'].pack('H*')                            # Critical Bit
    payload += [sprintf('%04x', key_length + 4)].pack('H*') # Payload Length (132)
    payload += Rex::Text.rand_text_alphanumeric(key_length) # Key Exchange Data
    # Nonce Payload
    payload += ['05'].pack('H*')                            # Next Payload (Identification)
    payload += ['00'].pack('H*')                            # Critical Bit
    payload += ['0018'].pack('H*')                          # Payload Length (24)
    payload += Rex::Text.rand_text_alphanumeric(20)         # Nonce DATA
    # Identification Payload
    payload += ['00'].pack('H*')                            # Next Payload (None)
    payload += ['00'].pack('H*')                            # Critical Bit
    payload += [id.length + 8].pack('n')                    # Payload Length (id + 8)
    payload += ['03'].pack('H*')                            # ID Type (USER_FQDN)
    payload += ['11'].pack('H*')                            # Protocol ID (UDP)
    payload += [port].pack('n')                             # Port (500)
    payload += id if id                                     # Identifier ID

    return payload
  end

  ENC_METHOD = {
    'DES'         => '80010001',
    'IDEA'        => '80010002',
    'BLOWFISH'    => '80010003',
    'RC5-R16-B64' => '80010004',
    '3DES'        => '80010005',
    'CAST'        => '80010006',
    'AES/128'     => ['80010007', '800E0080' ],
    'AES/192'     => ['80010007', '800E00C0' ],
    'AES/256'     => ['80010007', '800E0100' ]
  }

  HASH_ALGORITHM = {
    'MD5'      => '80020001',
    'SHA1'     => '80020002',
    'TIGER'    => '80020003',
    'SHA2-256' => '80020004',
    'SHA2-384' => '80020005',
    'SHA2-512' => '80020006'
  }

  AUTH_TYPE = {
    'PSK'    => '80030001',
    'RSA'    => '80030003',
    'ECDSA'  => '80030008',
    'HYBRID' => '8003FADD',
    'XAUTH'  => '8003FDE9'
  }

  GROUP_DESCRIPTION = {
    '768'  => '80040001',
    '1024' => '80040002',
    '1536' => '80040005',
    '2048' => '8004000E'
  }
end
