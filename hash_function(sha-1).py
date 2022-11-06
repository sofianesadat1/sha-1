import struct
import io

def _left_rotate(n,b):
    #rotate the integer n by b bits to the left    
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
    #example : rotate "10 111" by 2 bits = 111 00 | 000 10  

def _process_chunk(chunk, h0, h1, h2, h3, h4):

    assert len(chunk) == 64

    w= [0] * 80

    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i*4 + 4])[0]
    
    for i in range(16, 80):
        w[i] =  _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6    
    
        a, b, c, d, e = (_left_rotate(a,5) + f + e + w[i] + k, a,
                    _left_rotate(b, 30), c, d)
    
    h0 =(h0 + a) & 0xffffffff
    h1 =(h1 + b) & 0xffffffff
    h2 =(h2 + c) & 0xffffffff
    h3 =(h3 + d) & 0xffffffff
    h4 =(h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4


class Sha1Hash(object):

    def __init__(self):

        #iniate digest variables
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        #bytes object with 0 <= len <= 64 used to store the end of the message 
        #if the message lenght is not congruent to 64
        self._unprocessed = b'' 

        #length of all data in bytes that has been processed so far 
        self._message_byte_length = 0

    def update(self, arg):
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self
    
    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest()


    def _produce_digest(self):

        #preprocessing 
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        #append the bit '1' to the message =
        message += b'\x80'

        #appsend bytes so that the result of len(message) is congruent to 56 mod 64
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        #append the length of the message before preprocessing, in bit
        message += struct.pack(b'>Q', message_byte_length * 8)

        h = _process_chunk(message[:64], *self._h)

        if len(message) == 64: 
            return h 
        return _process_chunk(message[64:], *h)


def sha1(data):
    return Sha1Hash().update(data).hexdigest()
print(sha1(b'sofiane'))


