require "http/server"

module Kemal
  class Session
    # Writes the session cookie once per request, at the last moment it can
    # still be written.
    #
    # Session mutations only mark the store dirty (`Session#touch`), so a route
    # that sets twenty keys pays for one encryption instead of twenty. Something
    # has to perform that one write, and this handler is it — mutating a
    # request's session without it in the chain raises `HandlerRequired`:
    #
    #     use Kemal::Session::Handler.new
    #     Kemal.run
    #
    # ### Why it wraps the response output
    #
    # `Set-Cookie` is a header, so it has to be decided before the first byte of
    # the body reaches the socket. Crystal serializes the cookie jar into
    # headers on the first *unbuffered* write and silently ignores cookies added
    # afterwards, so committing after `call_next` would lose the session for any
    # response big enough to flush mid-route (the output buffer is 8 KB — an
    # ordinary HTML page).
    #
    # So instead of buffering the body, the handler wraps `response.output` and
    # commits just before the first write passes through: routes run to
    # completion before Kemal prints their return value, and streaming routes
    # commit at their first `print`. Responses with no body at all commit when
    # the handler unwinds. Mutating the session after that point raises
    # `ResponseAlreadySent` instead of quietly dropping the cookie.
    #
    # NOTE: `HTTP::Server::Response#upgrade` writes its headers directly rather
    # than through the output, so it is the one path this cannot intercept: a
    # session mutated inside a WebSocket handshake has nowhere to put its cookie.
    # Set the session in an ordinary route before opening the socket.
    class Handler
      include HTTP::Handler

      def call(context : HTTP::Server::Context)
        context.session_deferred = true
        context.response.output = CommitGuard.new(context.response.output, context)

        begin
          call_next(context)
        ensure
          # Nothing wrote a body (a bare 204, a `halt` with no content), so this
          # is the commit. `session?` avoids building — and decrypting — a
          # session for requests that never asked for one.
          context.session?.try(&.commit)
        end
      end

      # The `IO` that turns "before the first body byte" into a hook. It sits
      # outside `HTTP::Server::Response::Output`, so it sees writes before that
      # buffer does, and forwards `flush`/`close`/`closed?` as
      # `HTTP::Server::Response` requires of a wrapped output.
      private class CommitGuard < IO
        def initialize(@io : IO, @context : HTTP::Server::Context)
        end

        def write(slice : Bytes) : Nil
          commit
          @io.write(slice)
        end

        def read(slice : Bytes) : NoReturn
          raise IO::Error.new("Can't read from HTTP::Server::Response")
        end

        def flush : Nil
          commit
          @io.flush
        end

        # `ensure` because a session too big to fit a cookie raises here, and a
        # response whose output is left open never reaches the client at all.
        def close : Nil
          commit
        ensure
          @io.close
        end

        def closed? : Bool
          @io.closed?
        end

        # The context is marked sent whether or not a session exists yet: a route
        # that writes its body first and asks for a session afterwards has to be
        # told no, rather than handed one whose cookie can no longer be sent.
        private def commit : Nil
          @context.session?.try(&.commit)
          @context.session_sent = true
        end
      end
    end
  end
end
