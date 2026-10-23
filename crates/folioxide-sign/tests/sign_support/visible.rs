//! Visible signatures (M4 WP4.3A, brief §4.7, §6.2 "Visible", §6.3 suite `visible`): the
//! options, the B-T timestamper, readers of what a visible signature wrote, and the cases that
//! `visible_signing.rs` asserts and `oracle_visible.rs` hands to the oracles.

use folioxide_model::Rect;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::appearance::{ImagePosition, SignatureAppearance};
use folioxide_sign::bt::TimestampParams;
use folioxide_sign::docmdp::DocMdpPermissions;
use folioxide_sign::field::{FieldMode, FieldSpec, signature_fields};
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::tsp::Timestamper;
use folioxide_syntax::{Dict, ObjectId, Stream};
use folioxide_testkit::fixtures::{forms, syntax};
use folioxide_testkit::tsa::{MockTsa, MockTsaOptions};

use super::{open, p256, pki_text, repo, rsa2048, sign_with, time};

/// The widget rect of the visible cases, in default user space: below `minimal.pdf`'s text.
pub const RECT: [f64; 4] = [300.0, 100.0, 500.0, 160.0];

/// A widget rect 60 wide and 200 high in default user space: on a page turned by 90 or 270
/// degrees the reader sees it 200 wide and 60 high, like [`RECT`] upright.
pub const TALL_RECT: [f64; 4] = [300.0, 100.0, 360.0, 300.0];

/// [`RECT`] as a [`Rect`].
pub fn rect() -> Rect {
    let [a, b, c, d] = RECT;
    Rect::new(a, b, c, d)
}

/// The default options with a visible appearance at `rect`.
pub fn visible_at(rect: Rect) -> SignatureOptions {
    SignatureOptions::new(time()).with_appearance(Some(SignatureAppearance::new(rect)))
}

/// The bytes of `fixtures/images/<name>`.
pub fn image(name: &str) -> Vec<u8> {
    std::fs::read(repo().join("fixtures/images").join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The mock TSA of the test PKI (`tsa.pem`, `tsa.key.pem`), the root as extra certificate.
pub fn mock_tsa() -> MockTsa {
    let key = LocalSigner::from_pem(&pki_text("tsa.key.pem"), &pki_text("tsa.pem"), None)
        .expect("the TSA key");
    let cert = folioxide_sign::keys::certificates_from_pem(&pki_text("tsa.pem")).unwrap();
    let root = folioxide_sign::keys::certificates_from_pem(&pki_text("root.pem")).unwrap();
    MockTsa::new(
        cert[0].clone(),
        root,
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(MockTsaOptions::default())
}

/// A [`MockTsa`] as a [`Timestamper`].
pub struct Tsa(pub MockTsa);

impl Timestamper for Tsa {
    fn timestamp(&self, request_der: &[u8]) -> folioxide_sign::Result<Vec<u8>> {
        Ok(self.0.respond(request_der))
    }
}

/// Signs `source` B-T with `signer`, `options` and the mock TSA (a fixed nonce).
pub fn sign_bt(source: &[u8], signer: &dyn Signer, options: SignatureOptions) -> Vec<u8> {
    let tsa = Tsa(mock_tsa());
    let params = TimestampParams::new().with_nonce(Some(0x0102_0304_0506_0708));
    sign(
        &open(source),
        &SignRequest::new(signer, time())
            .with_options(options)
            .with_timestamper(&tsa, params),
    )
    .unwrap_or_else(|e| panic!("B-T signing failed: {e}"))
}

/// The field `name` of the newest revision of `pdf`: its object and dictionary.
pub fn field(pdf: &[u8], name: &str) -> (ObjectId, Dict) {
    let doc = open(pdf);
    let id = signature_fields(&doc)
        .unwrap()
        .into_iter()
        .find(|f| f.name == name)
        .and_then(|f| f.field)
        .unwrap_or_else(|| panic!("no field {name}"));
    let dict = doc.store().resolve(id).unwrap().as_dict().unwrap().clone();
    (id, dict)
}

/// The `/AP /N` form XObject of the widget `widget` of `pdf`: its object, the stream and its
/// decoded content.
pub fn normal_appearance(pdf: &[u8], widget: &Dict) -> (ObjectId, Stream, Vec<u8>) {
    let doc = open(pdf);
    let id = widget
        .get_dict(b"AP")
        .and_then(|ap| ap.get_ref(b"N"))
        .expect("an indirect /AP /N");
    let object = doc.store().resolve(id).unwrap();
    let stream = object.as_stream().expect("a stream").clone();
    let data = doc.store().stream_data(&stream).unwrap().data;
    (id, stream, data)
}

/// The resource `name` of category `category` (`Font`, `XObject`) of the form `stream`.
pub fn resource(stream: &Stream, category: &[u8], name: &[u8]) -> ObjectId {
    stream
        .dict
        .get_dict(b"Resources")
        .and_then(|r| r.get_dict(category))
        .and_then(|c| c.get_ref(name))
        .unwrap_or_else(|| panic!("no resource {}", String::from_utf8_lossy(name)))
}

/// The literal strings shown by `Tj` in `content`, unescaped (§7.3.4.2: `\(`, `\)`, `\\`).
pub fn shown_strings(content: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < content.len() {
        if content[i] != b'(' {
            i += 1;
            continue;
        }
        let mut text = Vec::new();
        let mut depth = 1;
        i += 1;
        while i < content.len() {
            match content[i] {
                b'\\' if i + 1 < content.len() => {
                    i += 1;
                    text.push(content[i]);
                }
                b'(' => {
                    depth += 1;
                    text.push(b'(');
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    text.push(b')');
                }
                byte => text.push(byte),
            }
            i += 1;
        }
        out.push(text);
        i += 1;
    }
    out
}

/// The font size of the first `Tf` of `content`.
pub fn font_size(content: &[u8]) -> f64 {
    let text = String::from_utf8_lossy(content);
    let line = text
        .lines()
        .find(|l| l.ends_with(" Tf"))
        .expect("a Tf operator");
    line.split(' ').nth(1).unwrap().parse().unwrap()
}

/// One visible-signature case: the file, the widget's page and rect (default user space).
pub struct VisibleCase {
    /// The case name (`visible-…`).
    pub name: &'static str,
    /// The signed file.
    pub pdf: Vec<u8>,
    /// The page of the visible widget.
    pub page: usize,
    /// The widget rect.
    pub rect: [f64; 4],
}

/// The cases of the `visible` oracle suite (brief §6.3): default text (RSA-2048), a JPEG on the
/// left (P-256), pages rotated by 90, 180 and 270 degrees, an existing visible field, a visible
/// signature followed by a second one, a visible approval after an invisible signature, a
/// visible B-T certification (P = 2), and an existing visible field signed after a P = 2
/// certification.
pub fn visible_cases() -> Vec<VisibleCase> {
    let rsa = rsa2048();
    let ec = p256();
    let case = |name, pdf, page, rect| VisibleCase {
        name,
        pdf,
        page,
        rect,
    };
    let existing = SignatureOptions::new(time())
        .with_field(
            FieldSpec::new()
                .with_name(Some(forms::VISIBLE.into()))
                .with_mode(FieldMode::ExistingOnly),
        )
        .with_appearance(Some(SignatureAppearance::for_existing_field()));
    let visible_rect = forms::VISIBLE_RECT.map(|v| v as f64);
    let mut cases = vec![
        case(
            "visible-rsa2048-default",
            sign_with(&syntax::minimal(), &rsa, visible_at(rect())),
            0,
            RECT,
        ),
        case(
            "visible-p256-image-left",
            sign_with(
                &syntax::minimal(),
                &ec,
                SignatureOptions::new(time()).with_appearance(Some(
                    SignatureAppearance::new(rect())
                        .with_image(Some(image("gray-baseline.jpg")))
                        .with_image_position(ImagePosition::Left),
                )),
            ),
            0,
            RECT,
        ),
    ];
    // On a page turned by 90 or 270 degrees the reader sees a user-space rect's height as its
    // width: the tall rect [`TALL_RECT`] shows as the same 200 x 60 box as `RECT` upright.
    for (page, name, rect) in [
        (1, "visible-rotate-90", TALL_RECT),
        (2, "visible-rotate-180", RECT),
        (3, "visible-rotate-270", TALL_RECT),
    ] {
        let [a, b, c, d] = rect;
        let options =
            visible_at(Rect::new(a, b, c, d)).with_field(FieldSpec::new().with_page(page));
        cases.push(case(
            name,
            sign_with(&forms::rotated_pages(), &rsa, options),
            page,
            rect,
        ));
    }
    cases.push(case(
        "visible-existing-field",
        sign_with(&forms::acroform(), &rsa, existing.clone()),
        0,
        visible_rect,
    ));
    let first = sign_with(&syntax::minimal(), &rsa, visible_at(rect()));
    cases.push(case(
        "visible-then-second-signature",
        sign_with(&first, &ec, SignatureOptions::new(time())),
        0,
        RECT,
    ));
    let invisible = sign_with(&syntax::minimal(), &rsa, SignatureOptions::new(time()));
    cases.push(case(
        "visible-after-invisible",
        sign_with(&invisible, &ec, visible_at(rect())),
        0,
        RECT,
    ));
    cases.push(case(
        "visible-bt-certified-p2",
        sign_bt(
            &syntax::minimal(),
            &rsa,
            visible_at(rect()).with_certification(Some(DocMdpPermissions::FormFilling)),
        ),
        0,
        RECT,
    ));
    let certified = sign_with(
        &forms::acroform(),
        &rsa,
        SignatureOptions::new(time()).with_certification(Some(DocMdpPermissions::FormFilling)),
    );
    cases.push(case(
        "visible-existing-field-after-certification",
        sign_with(&certified, &ec, existing),
        0,
        visible_rect,
    ));
    cases
}
