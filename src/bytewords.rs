//! Encode and decode byte payloads according to the [`bytewords`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md) scheme.
//!
//! The [`bytewords`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md) encoding
//! scheme defines three styles how byte payloads can be encoded.
//!
//! # Standard style
//! ```
//! use ur::bytewords::{decode, encode, Style};
//! let data = "Some bytes".as_bytes();
//! let encoded = encode(data, Style::Standard);
//! assert_eq!(
//!     encoded,
//!     "guru jowl join inch crux iced kick jury inch junk taxi aqua kite limp"
//! );
//! assert_eq!(data, decode(&encoded, Style::Standard).unwrap());
//! ```
//!
//! # URI style
//! ```
//! use ur::bytewords::{decode, encode, Style};
//! let data = "Some bytes".as_bytes();
//! let encoded = encode(data, Style::Uri);
//! assert_eq!(
//!     encoded,
//!     "guru-jowl-join-inch-crux-iced-kick-jury-inch-junk-taxi-aqua-kite-limp"
//! );
//! assert_eq!(data, decode(&encoded, Style::Uri).unwrap());
//! ```
//!
//! # Minimal style
//! ```
//! use ur::bytewords::{decode, encode, Style};
//! let data = "Some binary data".as_bytes();
//! let encoded = encode(data, Style::Minimal);
//! assert_eq!(encoded, "gujljnihcxidinjthsjpkkcxiehsjyhsnsgdmkht");
//! assert_eq!(data, decode(&encoded, Style::Minimal).unwrap());
//! ```

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const MINIMAL_WORD_LEN: usize = 2;
const WORD_LEN: usize = 4;

/// The three different `bytewords` encoding styles. See the [`encode`] documentation for examples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// Four-letter words, separated by spaces
    Standard,
    /// Four-letter words, separated by dashes
    Uri,
    /// Two-letter words, concatenated without separators
    Minimal,
}

/// The two different errors that can be returned when decoding.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Usually indicates a wrong encoding [`Style`] was passed.
    InvalidWord,
    /// The CRC32 checksum doesn't validate.
    InvalidChecksum,
    /// Invalid bytewords string length.
    InvalidLength,
    /// The bytewords string contains non-ASCII characters.
    NonAscii,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidWord => write!(f, "invalid word"),
            Error::InvalidChecksum => write!(f, "invalid checksum"),
            Error::InvalidLength => write!(f, "invalid length"),
            Error::NonAscii => write!(f, "bytewords string contains non-ASCII characters"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Decodes a `bytewords`-encoded String back into a byte payload. The encoding
/// must contain a four-byte checksum.
///
/// # Examples
///
/// ```
/// use ur::bytewords::{decode, Style};
/// assert_eq!(
///     decode("able tied also webs lung", Style::Standard).unwrap(),
///     vec![0]
/// );
/// assert_eq!(
///     decode("able-tied-also-webs-lung", Style::Uri).unwrap(),
///     vec![0]
/// );
/// // Notice how the minimal encoding consists of the start and end letters of the bytewords
/// assert_eq!(decode("aetdaowslg", Style::Minimal).unwrap(), vec![0]);
/// ```
///
/// # Errors
///
/// If the encoded string contains unrecognized words, is inconsistent with
/// the provided `style`, or contains an invalid checksum, an error will be
/// returned.
pub fn decode(encoded: &str, style: Style) -> Result<Vec<u8>, Error> {
    if !encoded.is_ascii() {
        return Err(Error::NonAscii);
    }

    let separator = match style {
        Style::Standard => ' ',
        Style::Uri => '-',
        Style::Minimal => return decode_minimal(encoded),
    };
    decode_from_index(&mut encoded.split(separator), false)
}

fn decode_minimal(encoded: &str) -> Result<Vec<u8>, Error> {
    if encoded.len() % MINIMAL_WORD_LEN != 0 {
        return Err(Error::InvalidLength);
    }

    decode_from_index(
        &mut (0..encoded.len())
            .step_by(MINIMAL_WORD_LEN)
            .map(|idx| encoded.get(idx..idx + MINIMAL_WORD_LEN).unwrap()),
        true,
    )
}

// Backported from dspicher/ur-rs, including full-word validation.
#[rustfmt::skip]
const BYTES_INDEXED_BY_HASH: [Option<u8>; 628] = [
    None, Some(101), None, None, None, None, Some(82), None, Some(41),
    Some(89), Some(127), None, None, Some(17), Some(65), None, Some(27),
    None, Some(124), None, Some(93), None, Some(57), None, Some(21), None,
    None, Some(32), Some(85), None, None, None, Some(137), Some(56), None,
    None, Some(59), None, Some(26), None, Some(123), Some(44), Some(96),
    Some(138), None, None, None, Some(61), None, None, None, None, None,
    None, Some(130), None, Some(106), Some(149), Some(58), Some(115),
    Some(160), Some(75), Some(125), Some(48), Some(91), Some(141), None,
    Some(105), Some(145), None, Some(111), None, Some(76), None, None,
    None, None, None, Some(103), None, None, None, Some(155), Some(77),
    Some(121), None, None, None, Some(50), None, None, Some(66),
    Some(109), Some(159), Some(83), None, None, Some(97), None,
    Some(177), None, Some(144), Some(67), Some(112), None, None, None,
    None, Some(90), Some(140), None, None, None, Some(68), Some(114),
    None, Some(79), Some(122), Some(162), None, None, None, Some(104),
    None, Some(64), None, None, None, Some(118), None, None, None,
    Some(168), None, Some(152), None, None, None, Some(81), Some(117),
    None, None, Some(134), Some(175), None, None, None, Some(113), None,
    None, None, None, None, Some(136), Some(176), None, None, Some(179),
    Some(110), None, None, None, None, Some(94), Some(133), None, None,
    Some(142), None, None, Some(153), None, Some(120), None, Some(194),
    None, None, None, Some(146), None, None, None, Some(186),
    Some(119), None, Some(203), Some(132), None, Some(102), None, None,
    None, Some(158), Some(181), None, Some(166), None, Some(131), None,
    Some(217), None, None, None, None, Some(188), None, None, None,
    Some(135), Some(170), Some(214), None, None, Some(116), None, None,
    None, Some(165), Some(193), Some(139), Some(174), None, Some(151),
    None, Some(108), None, Some(185), None, None, Some(204), None,
    Some(173), Some(210), Some(150), None, None, None, None, None, None,
    Some(202), None, None, Some(211), Some(147), None, None, Some(156),
    None, Some(230), None, None, None, None, None, None, None, None,
    Some(157), Some(187), None, None, None, Some(129), None, None,
    Some(148), None, Some(222), None, Some(183), None, Some(167), None,
    None, None, None, None, None, None, None, None, Some(231),
    Some(163), Some(197), None, Some(178), Some(208), Some(143), None,
    None, None, Some(190), Some(228), None, None, None, Some(172), None,
    None, None, None, None, Some(184), None, None, None, Some(234),
    Some(169), Some(207), None, None, None, Some(154), Some(182), None,
    None, Some(205), Some(237), None, Some(213), None, None, None,
    Some(248), None, None, Some(164), Some(201), Some(243), None, None,
    None, None, None, None, None, None, Some(161), Some(200), None,
    None, Some(218), None, None, None, None, Some(191), None, None,
    None, None, Some(4), Some(206), None, None, None, None, Some(192),
    None, None, Some(195), None, Some(171), Some(216), None, None,
    None, None, None, Some(227), Some(253), Some(196), None, None,
    None, None, Some(14), Some(220), None, None, None, None, Some(199),
    Some(244), Some(1), None, None, Some(20), None, None, None, None,
    Some(254), None, Some(233), Some(0), Some(215), None, Some(180),
    None, None, Some(29), Some(226), None, None, Some(235), None,
    Some(209), None, Some(11), Some(223), None, Some(189), None, None,
    Some(198), Some(241), None, None, None, Some(16), None, None, None,
    None, None, Some(37), None, Some(5), None, None, None, Some(221),
    Some(245), None, None, None, None, Some(236), None, None, None,
    Some(18), None, Some(247), Some(28), Some(232), None, None, None,
    None, None, None, None, None, None, Some(25), Some(224), None,
    None, None, None, Some(212), None, None, None, Some(246), None,
    None, None, Some(40), Some(239), None, Some(53), None, None, None,
    None, Some(23), None, Some(255), None, Some(240), Some(6), None,
    None, Some(10), Some(219), None, None, Some(229), None, None, None,
    None, Some(52), None, None, None, None, None, Some(73), Some(251),
    None, None, Some(2), None, None, None, Some(72), None, Some(30),
    Some(225), None, Some(39), None, None, None, None, Some(12),
    Some(69), None, Some(33), None, None, None, None, None, Some(49),
    None, None, None, Some(249), Some(22), Some(80), None, Some(36),
    Some(238), None, None, None, None, Some(70), None, Some(35),
    Some(74), Some(250), Some(47), Some(242), Some(9), None, Some(99),
    None, Some(63), None, None, None, Some(252), Some(46), Some(88),
    Some(7), None, None, None, None, None, Some(34), None, None,
    Some(43), Some(95), None, None, None, Some(15), None, None, None,
    Some(84), None, None, Some(86), None, Some(55), Some(98), Some(13),
    None, None, None, None, None, Some(45), Some(87), None, Some(54),
    Some(100), None, Some(71), None, Some(24), None, None, None,
    Some(92), Some(3), Some(51), None, None, Some(62), None, Some(31),
    None, Some(126), Some(42), None, Some(8), None, None, Some(19),
    Some(60), Some(107), None, Some(78), None, Some(38), None,
    Some(128),
];

fn encoded_byte(part: &str, minimal: bool) -> Option<u8> {
    let bytes = part.as_bytes();
    let expected_len = if minimal { MINIMAL_WORD_LEN } else { WORD_LEN };
    if bytes.len() != expected_len {
        return None;
    }
    let hash = usize::try_from(
        (25 * u32::from(bytes[0]) + 11 * u32::from(bytes[expected_len - 1]))
            % BYTES_INDEXED_BY_HASH.len() as u32,
    )
    .ok()?;
    let byte = BYTES_INDEXED_BY_HASH[hash]?;
    let expected = if minimal {
        crate::constants::MINIMALS[byte as usize]
    } else {
        crate::constants::WORDS[byte as usize]
    };
    (part == expected).then_some(byte)
}

fn decode_from_index(
    keys: &mut dyn Iterator<Item = &str>,
    minimal: bool,
) -> Result<Vec<u8>, Error> {
    strip_checksum(
        keys.map(|k| encoded_byte(k, minimal))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::InvalidWord)?,
    )
}

fn strip_checksum(mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    if data.len() < 4 {
        return Err(Error::InvalidChecksum);
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    if crate::crc32(payload).to_be_bytes() == checksum {
        data.truncate(data.len() - 4);
        Ok(data)
    } else {
        Err(Error::InvalidChecksum)
    }
}

/// Encodes a byte payload into a `bytewords` encoded String.
///
/// # Examples
///
/// ```
/// use ur::bytewords::{encode, Style};
/// assert_eq!(encode(&[0], Style::Standard), "able tied also webs lung");
/// assert_eq!(encode(&[0], Style::Uri), "able-tied-also-webs-lung");
/// // Notice how the minimal encoding consists of the start and end letters of the bytewords
/// assert_eq!(encode(&[0], Style::Minimal), "aetdaowslg");
/// ```
#[must_use]
pub fn encode(data: &[u8], style: Style) -> String {
    let checksum = crate::crc32(data).to_be_bytes();
    let data = data.iter().chain(checksum.iter());
    let words: Vec<&str> = match style {
        Style::Standard | Style::Uri => data
            .map(|&b| crate::constants::WORDS.get(b as usize).copied().unwrap())
            .collect(),
        Style::Minimal => data
            .map(|&b| crate::constants::MINIMALS.get(b as usize).copied().unwrap())
            .collect(),
    };
    let separator = match style {
        Style::Standard => " ",
        Style::Uri => "-",
        Style::Minimal => "",
    };
    words.join(separator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc() {
        assert_eq!(crate::crc32(b""), 0);
        assert_eq!(crate::crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crate::crc32(b"Hello, world!"), 0xebe6_c6e6);
        assert_eq!(crate::crc32(b"Wolf"), 0x598c_84dc);
    }

    #[test]
    fn test_byteword_lookup_entries_and_minimal_pairs() {
        for (index, word) in crate::constants::WORDS.iter().enumerate() {
            let byte = u8::try_from(index).unwrap();
            assert_eq!(encoded_byte(word, false), Some(byte));
            assert_eq!(
                encoded_byte(crate::constants::MINIMALS[index], true),
                Some(byte),
            );
        }

        for first in b'a'..=b'z' {
            for last in b'a'..=b'z' {
                let bytes = [first, last];
                let pair = std::str::from_utf8(&bytes).unwrap();
                let expected = crate::constants::MINIMALS
                    .iter()
                    .position(|word| *word == pair)
                    .map(|index| u8::try_from(index).unwrap());
                assert_eq!(encoded_byte(pair, true), expected, "{pair}");
            }
        }
    }

    #[test]
    fn test_full_words_validate_the_middle_letters() {
        for word in crate::constants::WORDS {
            for position in [1, 2] {
                for letter in b'a'..=b'z' {
                    let mut bytes: [u8; WORD_LEN] = word.as_bytes().try_into().unwrap();
                    bytes[position] = letter;
                    let changed = std::str::from_utf8(&bytes).unwrap();
                    let expected = crate::constants::WORDS
                        .iter()
                        .position(|word| *word == changed)
                        .map(|index| u8::try_from(index).unwrap());
                    assert_eq!(encoded_byte(changed, false), expected, "{changed}");
                }
            }
        }
    }

    #[test]
    fn test_byteword_invalid_input_errors() {
        for non_ascii in ["é", "aé", "한", "한글", "🦀", "a\u{301}"] {
            for style in [Style::Standard, Style::Uri, Style::Minimal] {
                assert_eq!(decode(non_ascii, style), Err(Error::NonAscii));
            }
        }
        for (input, style, expected) in [
            ("", Style::Standard, Error::InvalidWord),
            ("", Style::Minimal, Error::InvalidChecksum),
            ("a", Style::Minimal, Error::InvalidLength),
            ("aa", Style::Minimal, Error::InvalidChecksum),
            ("ab", Style::Minimal, Error::InvalidWord),
            ("ae", Style::Standard, Error::InvalidWord),
            ("able", Style::Standard, Error::InvalidChecksum),
            ("ABLE", Style::Standard, Error::InvalidWord),
            ("AE", Style::Minimal, Error::InvalidWord),
            ("able--acid", Style::Uri, Error::InvalidWord),
        ] {
            assert_eq!(decode(input, style), Err(expected));
        }
    }

    #[test]
    fn test_bytewords() {
        let input = vec![0, 1, 2, 128, 255];
        assert_eq!(
            encode(&input, Style::Standard),
            "able acid also lava zoom jade need echo taxi"
        );
        assert_eq!(
            encode(&input, Style::Uri),
            "able-acid-also-lava-zoom-jade-need-echo-taxi"
        );
        assert_eq!(encode(&input, Style::Minimal), "aeadaolazmjendeoti");

        assert_eq!(
            decode(
                "able acid also lava zoom jade need echo taxi",
                Style::Standard
            )
            .unwrap(),
            input
        );
        assert_eq!(
            decode("able-acid-also-lava-zoom-jade-need-echo-taxi", Style::Uri).unwrap(),
            input
        );
        assert_eq!(decode("aeadaolazmjendeoti", Style::Minimal).unwrap(), input);

        // empty payload is allowed
        decode(&encode(&[], Style::Minimal), Style::Minimal).unwrap();

        // bad checksum
        assert_eq!(
            decode(
                "able acid also lava zero jade need echo wolf",
                Style::Standard
            )
            .unwrap_err(),
            Error::InvalidChecksum
        );
        assert_eq!(
            decode("able-acid-also-lava-zero-jade-need-echo-wolf", Style::Uri).unwrap_err(),
            Error::InvalidChecksum
        );
        assert_eq!(
            decode("aeadaolazojendeowf", Style::Minimal).unwrap_err(),
            Error::InvalidChecksum
        );

        // too short
        assert_eq!(
            decode("wolf", Style::Standard).unwrap_err(),
            Error::InvalidChecksum
        );
        assert_eq!(decode("", Style::Standard).unwrap_err(), Error::InvalidWord);

        // invalid length
        assert_eq!(
            decode("aea", Style::Minimal).unwrap_err(),
            Error::InvalidLength
        );

        // non ASCII
        assert_eq!(decode("₿", Style::Standard).unwrap_err(), Error::NonAscii);
        assert_eq!(decode("₿", Style::Uri).unwrap_err(), Error::NonAscii);
        assert_eq!(decode("₿", Style::Minimal).unwrap_err(), Error::NonAscii);
    }

    #[test]
    fn test_encoding() {
        let input: [u8; 100] = [
            245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212,
            19, 159, 17, 37, 239, 240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242,
            254, 147, 204, 66, 163, 216, 175, 191, 72, 169, 54, 32, 60, 144, 230, 210, 137, 184,
            197, 33, 113, 88, 14, 157, 31, 177, 46, 1, 115, 205, 69, 225, 150, 65, 235, 58, 144,
            65, 240, 133, 69, 113, 247, 63, 53, 242, 165, 160, 144, 26, 13, 79, 237, 133, 71, 82,
            69, 254, 165, 138, 41, 85, 24,
        ];

        let encoded = "yank toys bulb skew when warm free fair tent swan \
                       open brag mint noon jury list view tiny brew note \
                       body data webs what zinc bald join runs data whiz \
                       days keys user diet news ruby whiz zone menu surf \
                       flew omit trip pose runs fund part even crux fern \
                       math visa tied loud redo silk curl jugs hard beta \
                       next cost puma drum acid junk swan free very mint \
                       flap warm fact math flap what limp free jugs yell \
                       fish epic whiz open numb math city belt glow wave \
                       limp fuel grim free zone open love diet gyro cats \
                       fizz holy city puff";

        let encoded_minimal = "yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwne\
                               bydawswtzcbdjnrsdawzdsksurdtnsrywzzemusf\
                               fwottppersfdptencxfnmhvatdldroskcljshdba\
                               ntctpadmadjksnfevymtfpwmftmhfpwtlpfejsyl\
                               fhecwzonnbmhcybtgwwelpflgmfezeonledtgocs\
                               fzhycypf";

        assert_eq!(decode(encoded, Style::Standard).unwrap(), input.to_vec());
        assert_eq!(
            decode(encoded_minimal, Style::Minimal).unwrap(),
            input.to_vec()
        );
        assert_eq!(encode(&input, Style::Standard), encoded);
        assert_eq!(encode(&input, Style::Minimal), encoded_minimal);
    }
}
