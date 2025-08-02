using System;

namespace pqproxy.server.Core.Middleware;

internal sealed class PrebufferStream : Stream
{
    private ReadOnlyMemory<byte> _prefix;
    private readonly Stream      _inner;
    public PrebufferStream(Stream inner, ReadOnlyMemory<byte> prefix)
    {
        _inner  = inner;
        _prefix = prefix;
    }

    public override bool CanRead  => true;
    public override bool CanWrite => true;
    public override bool CanSeek  => false;
    public override long Length   => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_prefix.Length == 0)
            return _inner.Read(buffer, offset, count);

        int n = Math.Min(count, _prefix.Length);
        _prefix.Span.Slice(0, n).CopyTo(buffer.AsSpan(offset, n));
        _prefix = _prefix.Slice(n);
        return n;
    }

    public override void Write(byte[] buffer, int offset, int count)
        => _inner.Write(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        => _inner.WriteAsync(buffer, ct);

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
    public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
    public override void SetLength(long value)      => throw new NotSupportedException();

    protected override void Dispose(bool d)
    {
        if (d) _inner.Dispose();
        base.Dispose(d);
    }
}
