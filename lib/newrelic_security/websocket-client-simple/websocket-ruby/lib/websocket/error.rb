# frozen_string_literal: true

module NewRelic::Security::WebSocket
  class Error < RuntimeError
    class Frame < NewRelic::Security::WebSocket::Error
      class ControlFramePayloadTooLong < NewRelic::Security::WebSocket::Error::Frame
        def message
          :control_frame_payload_too_long
        end
      end

      class DataFrameInsteadContinuation < NewRelic::Security::WebSocket::Error::Frame
        def message
          :data_frame_instead_continuation
        end
      end

      class FragmentedControlFrame < NewRelic::Security::WebSocket::Error::Frame
        def message
          :fragmented_control_frame
        end
      end

      class Invalid < NewRelic::Security::WebSocket::Error::Frame
        def message
          :invalid_frame
        end
      end

      class InvalidPayloadEncoding < NewRelic::Security::WebSocket::Error::Frame
        def message
          :invalid_payload_encoding
        end
      end

      class MaskTooShort < NewRelic::Security::WebSocket::Error::Frame
        def message
          :mask_is_too_short
        end
      end

      class ReservedBitUsed < NewRelic::Security::WebSocket::Error::Frame
        def message
          :reserved_bit_used
        end
      end

      class TooLong < NewRelic::Security::WebSocket::Error::Frame
        def message
          :frame_too_long
        end
      end

      class UnexpectedContinuationFrame < NewRelic::Security::WebSocket::Error::Frame
        def message
          :unexpected_continuation_frame
        end
      end

      class UnknownFrameType < NewRelic::Security::WebSocket::Error::Frame
        def message
          :unknown_frame_type
        end
      end

      class UnknownOpcode < NewRelic::Security::WebSocket::Error::Frame
        def message
          :unknown_opcode
        end
      end

      class UnknownCloseCode < NewRelic::Security::WebSocket::Error::Frame
        def message
          :unknown_close_code
        end
      end

      class UnknownVersion < NewRelic::Security::WebSocket::Error::Frame
        def message
          :unknown_protocol_version
        end
      end
    end

    class Handshake < NewRelic::Security::WebSocket::Error
      class GetRequestRequired < NewRelic::Security::WebSocket::Error::Handshake
        def message
          :get_request_required
        end
      end

      class InvalidAuthentication < NewRelic::Security::WebSocket::Error::Handshake
        def message
          :invalid_handshake_authentication
        end
      end

      class InvalidHeader < NewRelic::Security::WebSocket::Error::Handshake
        def message
          :invalid_header
        end
      end

      class UnsupportedProtocol < NewRelic::Security::WebSocket::Error::Handshake
        def message
          :unsupported_protocol
        end
      end

      class InvalidStatusCode < NewRelic::Security::WebSocket::Error::Handshake
        def message
          :invalid_status_code
        end
      end

      class NoHostProvided < NewRelic::Security::WebSocket::Error::Handshake
        def message
          :no_host_provided
        end
      end

      class UnknownVersion < NewRelic::Security::WebSocket::Error::Handshake
        def message
          :unknown_protocol_version
        end
      end
    end
  end
end
