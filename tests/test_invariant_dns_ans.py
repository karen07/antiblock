import pytest
import struct
import ctypes


# Simulated DNS message handler that mirrors the vulnerable pattern
# This represents the security boundary we're testing

MAX_BUFFER_SIZE = 512  # Typical DNS max buffer size


class DNSReceiveMsg:
    """Simulates the receive_msg structure from dns_ans.c"""
    
    def __init__(self, max_size=MAX_BUFFER_SIZE):
        self.max_size = max_size
        self.data = bytearray(max_size)
        self.size = 0
    
    def safe_copy(self, source_data, claimed_size):
        """
        Safe implementation: must verify size <= max_size before copy.
        This is what the fixed code SHOULD do.
        """
        if claimed_size > self.max_size:
            raise ValueError(
                f"Buffer overflow prevented: claimed_size={claimed_size} "
                f"exceeds max_size={self.max_size}"
            )
        if claimed_size < 0:
            raise ValueError(f"Invalid size: {claimed_size}")
        if claimed_size > len(source_data):
            raise ValueError(
                f"Claimed size {claimed_size} exceeds actual data length {len(source_data)}"
            )
        # Safe copy - only copy up to max_size
        copy_len = min(claimed_size, self.max_size)
        self.data[:copy_len] = source_data[:copy_len]
        self.size = copy_len
        return copy_len


def simulate_dns_response_processing(payload_data, claimed_size):
    """
    Simulates the DNS response processing from dns_ans.c.
    Returns (success, bytes_copied, error) tuple.
    """
    msg = DNSReceiveMsg(max_size=MAX_BUFFER_SIZE)
    
    try:
        bytes_copied = msg.safe_copy(payload_data, claimed_size)
        return True, bytes_copied, None
    except ValueError as e:
        return False, 0, str(e)


# Adversarial payloads: (payload_data, claimed_size, description)
ADVERSARIAL_PAYLOADS = [
    # Oversized claimed_size - classic heap buffer overflow attempt
    (b"A" * 512, 513, "claimed_size one byte over max"),
    (b"A" * 512, 1024, "claimed_size double the max"),
    (b"A" * 512, 65535, "claimed_size max UDP DNS response"),
    (b"A" * 512, 65536, "claimed_size exceeds UDP max"),
    (b"A" * 512, 2**31 - 1, "claimed_size INT_MAX"),
    (b"A" * 512, 2**32 - 1, "claimed_size UINT_MAX"),
    (b"A" * 512, 2**63 - 1, "claimed_size very large positive"),
    
    # Negative/underflow sizes
    (b"A" * 512, -1, "negative size -1"),
    (b"A" * 512, -512, "negative size -512"),
    (b"A" * 512, -(2**31), "negative size INT_MIN"),
    
    # Zero size (edge case)
    (b"", 0, "zero size empty payload"),
    
    # Exact boundary
    (b"A" * 512, 512, "exact max_size boundary"),
    (b"A" * 511, 511, "one under max_size"),
    
    # Spoofed DNS response with crafted header claiming large size
    (
        b"\x00\x01"  # Transaction ID
        b"\x81\x80"  # Flags: standard response
        b"\x00\x01"  # Questions: 1
        b"\x00\x01"  # Answers: 1
        b"\x00\x00"  # Authority: 0
        b"\x00\x00"  # Additional: 0
        + b"\x03www\x07example\x03com\x00"  # Query name
        + b"\x00\x01\x00\x01"  # Type A, Class IN
        + b"A" * (512 - 30),  # Padding to fill buffer
        1024,  # Claimed size larger than actual
        "spoofed DNS response with oversized claimed length"
    ),
    
    # Malformed DNS response with size mismatch
    (b"\xff" * 100, 600, "small payload with large claimed size"),
    (b"\x00" * 512, 513, "null bytes with overflow size"),
    
    # DNS amplification attack simulation
    (b"\x00" * 512, 4096, "DNS amplification - 8x size claim"),
    
    # Crafted to exploit integer overflow in size calculation
    (b"X" * 512, 2**32 - MAX_BUFFER_SIZE + 1, "integer overflow boundary"),
    (b"X" * 512, 2**32 - 1, "UINT32_MAX overflow"),
    
    # Payload larger than max but with exact max claimed (should succeed)
    (b"B" * 1024, 512, "oversized payload but valid claimed size"),
    
    # Empty payload with nonzero claimed size
    (b"", 1, "empty payload nonzero claimed size"),
    (b"", 512, "empty payload max claimed size"),
]


@pytest.mark.parametrize("payload_data,claimed_size,description", ADVERSARIAL_PAYLOADS)
def test_dns_buffer_copy_size_invariant(payload_data, claimed_size, description):
    """
    Invariant: The number of bytes copied into the DNS receive buffer must NEVER
    exceed max_size (MAX_BUFFER_SIZE). Any operation that would copy more bytes
    than the allocated buffer size must be rejected or safely truncated.
    This prevents heap buffer overflow via DNS spoofing with crafted response sizes.
    """
    success, bytes_copied, error = simulate_dns_response_processing(
        payload_data, claimed_size
    )
    
    # INVARIANT 1: Bytes actually copied must never exceed max buffer size
    assert bytes_copied <= MAX_BUFFER_SIZE, (
        f"SECURITY VIOLATION [{description}]: "
        f"Copied {bytes_copied} bytes into buffer of size {MAX_BUFFER_SIZE}. "
        f"Heap buffer overflow condition detected!"
    )
    
    # INVARIANT 2: If claimed_size > max_size, the operation must fail or be bounded
    if claimed_size > MAX_BUFFER_SIZE:
        assert not success or bytes_copied <= MAX_BUFFER_SIZE, (
            f"SECURITY VIOLATION [{description}]: "
            f"Oversized copy succeeded with claimed_size={claimed_size} "
            f"exceeding max_size={MAX_BUFFER_SIZE}"
        )
    
    # INVARIANT 3: Negative sizes must always be rejected
    if claimed_size < 0:
        assert not success, (
            f"SECURITY VIOLATION [{description}]: "
            f"Negative claimed_size={claimed_size} was accepted. "
            f"Integer underflow/overflow attack vector!"
        )
        assert bytes_copied == 0, (
            f"SECURITY VIOLATION [{description}]: "
            f"Bytes were copied despite negative claimed_size={claimed_size}"
        )
    
    # INVARIANT 4: Claimed size must not exceed actual data length (prevents read overflow)
    if claimed_size > len(payload_data) and claimed_size > 0:
        assert not success or bytes_copied <= len(payload_data), (
            f"SECURITY VIOLATION [{description}]: "
            f"Read beyond actual data: claimed={claimed_size}, "
            f"actual_data_len={len(payload_data)}, copied={bytes_copied}"
        )
    
    # INVARIANT 5: bytes_copied must always be non-negative
    assert bytes_copied >= 0, (
        f"SECURITY VIOLATION [{description}]: "
        f"Negative bytes_copied={bytes_copied} indicates integer underflow"
    )


@pytest.mark.parametrize("max_size,claimed_size", [
    (512, 512),      # exact boundary - must succeed
    (512, 511),      # under boundary - must succeed  
    (512, 1),        # minimal valid - must succeed
    (512, 0),        # zero - must succeed
])
def test_dns_buffer_valid_sizes_accepted(max_size, claimed_size):
    """
    Invariant: Valid sizes within bounds must be accepted to ensure
    the security fix does not break legitimate DNS responses.
    """
    payload = b"A" * max_size
    msg = DNSReceiveMsg(max_size=max_size)
    
    try:
        bytes_copied = msg.safe_copy(payload, claimed_size)
        assert bytes_copied == claimed_size, (
            f"Expected {claimed_size} bytes copied, got {bytes_copied}"
        )
        assert bytes_copied <= max_size, (
            f"Buffer overflow: {bytes_copied} > {max_size}"
        )
    except ValueError as e:
        pytest.fail(
            f"Valid size {claimed_size} was incorrectly rejected for "
            f"max_size={max_size}: {e}"
        )


def test_dns_buffer_overflow_detection_comprehensive():
    """
    Invariant: Under no adversarial input combination should the buffer
    copy operation write beyond the allocated buffer boundary.
    This is the core security property preventing heap corruption.
    """
    msg = DNSReceiveMsg(max_size=MAX_BUFFER_SIZE)
    
    # Verify the buffer is exactly max_size
    assert len(msg.data) == MAX_BUFFER_SIZE
    
    # Attempt multiple overflow scenarios
    overflow_attempts = [
        MAX_BUFFER_SIZE + 1,
        MAX_BUFFER_SIZE * 2,
        MAX_BUFFER_SIZE * 100,
        65535,  # Max DNS UDP
        2**16,
        2**32 - 1,
    ]
    
    for overflow_size in overflow_attempts:
        large_payload = b"X" * min(overflow_size, 65536)  # Cap actual data for test
        
        with pytest.raises(ValueError, match="Buffer overflow prevented|Invalid size|Claimed size"):
            msg.safe_copy(large_payload, overflow_size)
        
        # Buffer must remain intact after failed attempt
        assert len(msg.data) == MAX_BUFFER_SIZE, (
            f"Buffer size changed after overflow attempt with size={overflow_size}!"
        )