require_relative 'ethon'

typh_lib = File.expand_path('../typhoeus/lib', __FILE__)
$LOAD_PATH.unshift(typh_lib)

require_relative 'typhoeus/lib/typhoeus'
