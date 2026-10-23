// Type tests, checked with `tsc --noEmit -p test` (pnpm test:types). Nothing here is executed.

import {
  FolioxideError,
  LocalSigner,
  PdfDocument,
  PreparedSignature,
  fromPdfDate,
  isSignatureAcceptable,
  signPdf,
  toPdfDate,
  version,
} from 'folioxide'
import type {
  AppearanceFont,
  CertificateInfo,
  Coverage,
  Diagnostic,
  DiagnosticKind,
  DigestAlg,
  DocInfo,
  DocMdpLevel,
  ErrorCode,
  ExternalSigner,
  FieldMode,
  ImagePosition,
  IncrementalSaveOptions,
  InfoUpdate,
  KeyDescription,
  ModificationLevel,
  ObjectRef,
  OpenOptions,
  PadesLevel,
  PageBox,
  PageInfo,
  PdfDateInput,
  PrepareSignatureOptions,
  ProblemCode,
  Rect,
  SaveOptions,
  SigAlg,
  SignPdfOptions,
  SignatureAppearanceOptions,
  SignatureFieldSpec,
  SignatureKind,
  SignatureProblem,
  SignatureReport,
  StreamCompression,
  SubFilter,
  TimestampCallback,
  TimestampInfo,
  TimestampRequestOptions,
  Trapped,
  VerifyOptions,
  XrefStyle,
} from 'folioxide'
import * as binding from '../binding.js'

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false

// ---- version() ---------------------------------------------------------------------------------

const v: string = version()
const facadeSignature: Equal<typeof version, () => string> = true

// @ts-expect-error version() takes no arguments
version('0.1.0')

// @ts-expect-error the result is a string, not a number
const n: number = version()

// The generated binding declares the same signature as the hand-written facade.
const bindingSignature: Equal<typeof binding.version, typeof version> = true

// ---- opening and creating ----------------------------------------------------------------------

declare const bytes: Uint8Array
declare const buffer: Buffer

const opened: PdfDocument = PdfDocument.open(bytes)
const openedStrict: PdfDocument = PdfDocument.open(buffer, { strict: true })
const openedAsync: Promise<PdfDocument> = PdfDocument.openAsync(bytes, { strict: false })
const created: PdfDocument = PdfDocument.create()
const openOptions: OpenOptions = {}

// @ts-expect-error the data is bytes, not a string
PdfDocument.open('%PDF-1.7')
// @ts-expect-error strict is a boolean
PdfDocument.open(bytes, { strict: 'yes' })
// @ts-expect-error documents come from open, openAsync or create
new PdfDocument()

// ---- reading -----------------------------------------------------------------------------------

const pageCount: number = opened.pageCount
const pdfVersion: string = opened.version
const isModified: boolean = opened.isModified
// @ts-expect-error pageCount is read-only
opened.pageCount = 3

// ---- memory ------------------------------------------------------------------------------------

const nativeMemory: number = opened.nativeMemory
const isClosed: boolean = opened.isClosed
// @ts-expect-error nativeMemory is read-only
opened.nativeMemory = 0
const closeResult: void = opened.close()
const disposeResult: void = opened[Symbol.dispose]()
const disposable: Disposable = opened

const page: PageInfo = opened.getPage(0)
const pageShape: Equal<
  PageInfo,
  { index: number; width: number; height: number; mediaBox: Rect; cropBox: Rect; rotation: number }
> = true
const rectShape: Equal<Rect, { llx: number; lly: number; urx: number; ury: number }> = true

const info: DocInfo = opened.getInfo()
const title: string | undefined = info.title
const creationDate: string | undefined = info.creationDate
const trapped: Trapped | undefined = info.trapped
const custom: Record<string, string> = info.custom
const trappedValues: Equal<Trapped, 'true' | 'false' | 'unknown'> = true

const diagnostics: Diagnostic[] = opened.diagnostics()
const firstDiagnostic: Diagnostic | undefined = diagnostics[0]
const offset: number | null | undefined = firstDiagnostic?.offset
const kind: DiagnosticKind | undefined = firstDiagnostic?.kind
const someKind: DiagnosticKind = 'xrefReconstructed'
// @ts-expect-error not a diagnostic kind
const notAKind: DiagnosticKind = 'somethingElse'

// ---- editing -----------------------------------------------------------------------------------

const update: InfoUpdate = {
  title: 'Отчёт 年度報告',
  author: null,
  creationDate: new Date(),
  modDate: 'D:20261010093000Z',
  trapped: 'unknown',
  custom: { Department: 'Finance', Obsolete: null },
}
opened.setInfo(update)
opened.setInfo({})
const dateInput: Equal<PdfDateInput, Date | string> = true
// @ts-expect-error trapped is 'true', 'false' or 'unknown'
opened.setInfo({ trapped: 'maybe' })
// @ts-expect-error a title is text
opened.setInfo({ title: 42 })
// @ts-expect-error custom values are text or null
opened.setInfo({ custom: { Key: 1 } })

opened.setPageRotation(0, -90)
opened.setPageBox(0, 'crop', { llx: 0, lly: 0, urx: 300, ury: 400 })
opened.setPageBox(0, 'crop', null)
const pageBox: Equal<PageBox, 'media' | 'crop'> = true
// @ts-expect-error only the media box and the crop box
opened.setPageBox(0, 'bleed', null)
// @ts-expect-error the rectangle is required (null removes the crop box)
opened.setPageBox(0, 'crop')

// ---- saving ------------------------------------------------------------------------------------

const saveOptions: SaveOptions = {
  xref: 'stream',
  objectStreams: true,
  compress: 'recompress',
  gc: true,
  renumber: true,
  deterministic: true,
  id: [bytes, buffer],
  minVersion: '1.7',
  flateLevel: 9,
}
const saved: Buffer = opened.save(saveOptions)
const savedDefault: Buffer = created.save()
const savedAsync: Promise<Buffer> = opened.saveAsync({ xref: 'table' })
const xrefStyles: Equal<XrefStyle, 'auto' | 'table' | 'stream'> = true
const compressions: Equal<StreamCompression, 'keep' | 'compressNew' | 'recompress'> = true
// @ts-expect-error xref styles are lower case
opened.save({ xref: 'Table' })
// @ts-expect-error minVersion is a version string such as "1.7"
opened.save({ minVersion: 1.7 })

const incrementalOptions: IncrementalSaveOptions = { suffixOnly: true, deterministic: true, id1: bytes }
const incremental: Buffer = opened.saveIncremental()
const suffix: Buffer = opened.saveIncremental(incrementalOptions)
const incrementalAsync: Promise<Buffer> = opened.saveIncrementalAsync()

// ---- errors and dates --------------------------------------------------------------------------

declare const caught: unknown
if (caught instanceof FolioxideError) {
  const code: ErrorCode = caught.code
  const asError: Error = caught
  const details: Record<string, unknown> | undefined = caught.details
  void [code, asError, details]
}
const busy: ErrorCode = 'E_BUSY'
const closedCode: ErrorCode = 'E_CLOSED'
const syntax: ErrorCode = 'E_SYNTAX'
// @ts-expect-error not an error code
const notACode: ErrorCode = 'E_NOPE'
const constructed = new FolioxideError('E_IO', 'message', { cause: new Error('inner'), details: { path: 'x' } })
// @ts-expect-error the code must be an ErrorCode
new FolioxideError('NOPE', 'message')

const pdfDate: string = toPdfDate(new Date())
const parsed: Date | null = fromPdfDate('D:2026')
// @ts-expect-error toPdfDate takes a Date
toPdfDate('2026-10-10')

// ---- signing: LocalSigner ----------------------------------------------------------------------

const p12Signer: LocalSigner = LocalSigner.fromPkcs12(bytes, 'password')
const pemSigner: LocalSigner = LocalSigner.fromPem('-----BEGIN PRIVATE KEY-----', buffer, 'password')
const pemSignerNoPassword: LocalSigner = LocalSigner.fromPem('key', 'certs')
const signerChain: Buffer[] = p12Signer.certificateChain
const signerAlgorithm: SigAlg = p12Signer.algorithm
const signerDigest: DigestAlg = p12Signer.defaultDigest
const signedBytes: Buffer = p12Signer.sign(bytes)
const signedBytesSha384: Buffer = p12Signer.sign(bytes, 'sha384')
const signedAsync: Promise<Buffer> = pemSigner.signAsync(buffer, 'sha512')
const sigAlgs: Equal<SigAlg, 'rsa-pkcs1v15' | 'ecdsa'> = true
const digestAlgs: Equal<DigestAlg, 'sha256' | 'sha384' | 'sha512'> = true
// @ts-expect-error SHA-1 is never used to sign
p12Signer.sign(bytes, 'sha1')
// Secrets as bytes, which the caller can wipe.
const p12SignerBytes: LocalSigner = LocalSigner.fromPkcs12(bytes, buffer)
const pemSignerBytes: LocalSigner = LocalSigner.fromPem(buffer, 'certs', bytes)
// @ts-expect-error the password is a string or bytes
LocalSigner.fromPkcs12(bytes, 42)
// @ts-expect-error the key password is a string or bytes
LocalSigner.fromPem('key', 'certs', 42)
p12SignerBytes.close()
pemSignerBytes[Symbol.dispose]()
const signerClosed: boolean = p12SignerBytes.isClosed
// @ts-expect-error isClosed is read-only
p12SignerBytes.isClosed = true
// @ts-expect-error signers come from fromPkcs12 or fromPem
new LocalSigner()
// @ts-expect-error the chain is read-only
p12Signer.certificateChain = []

// ---- signing: the two phases -------------------------------------------------------------------

const prepareOptions: PrepareSignatureOptions = {
  certificateChain: [bytes, buffer],
  algorithm: 'ecdsa',
  digest: 'sha384',
  signingTime: new Date(),
  field: { name: 'Approval', page: 0, mode: 'createOrUse' },
  subFilter: 'ETSI.CAdES.detached',
  name: 'Jane',
  reason: 'Approved',
  location: 'Berlin',
  contactInfo: 'jane@example.com',
  contentsReserve: 16384,
}
const minimalPrepareOptions: PrepareSignatureOptions = { certificateChain: [bytes], algorithm: 'rsa-pkcs1v15' }
const stringTime: PrepareSignatureOptions = { ...minimalPrepareOptions, signingTime: 'D:20261010120000Z' }
const prepared: PreparedSignature = opened.prepareSignature(prepareOptions)
const preparedAsync: Promise<PreparedSignature> = opened.prepareSignatureAsync(minimalPrepareOptions)
const toBeSigned: Buffer = prepared.toBeSigned
const toBeSignedDigest: Buffer = prepared.toBeSignedDigest
const toBeSignedDigestInfo: Buffer = prepared.toBeSignedDigestInfo
const preparedDigest: DigestAlg = prepared.digestAlgorithm
const preparedAlgorithm: SigAlg = prepared.algorithm
const preparedSubFilter: SubFilter = prepared.subFilter
const capacity: number = prepared.contentsCapacity
const byteRange: number[] = prepared.byteRange
const preparedWarnings: string[] = prepared.warnings
const isFinished: boolean = prepared.isFinished
const finished: Buffer = prepared.finish(bytes)
const finishedAsync: Promise<Buffer> = prepared.finishAsync(buffer)
const embedded: Buffer = prepared.embedCms(bytes)
const embeddedAsync: Promise<Buffer> = prepared.embedCmsAsync(bytes)
const serialized: Buffer = prepared.serialize()
const deserialized: PreparedSignature = PreparedSignature.deserialize(serialized)
const subFilters: Equal<SubFilter, 'ETSI.CAdES.detached' | 'adbe.pkcs7.detached'> = true
const fieldModes: Equal<FieldMode, 'createOrUse' | 'existingOnly' | 'createOnly'> = true
const fieldSpec: SignatureFieldSpec = {}
// @ts-expect-error the bytes to sign are read-only
prepared.toBeSigned = buffer
// @ts-expect-error prepared signatures come from prepareSignature or deserialize
new PreparedSignature()
// @ts-expect-error the algorithm is required
opened.prepareSignature({ certificateChain: [bytes] })
// @ts-expect-error SubFilter names are case-sensitive PDF names
opened.prepareSignature({ ...minimalPrepareOptions, subFilter: 'etsi.cades.detached' })
// @ts-expect-error the field mode is one of three
opened.prepareSignature({ ...minimalPrepareOptions, field: { mode: 'replace' } })

// ---- signing: signPdf ------------------------------------------------------------------------

const external: ExternalSigner = {
  certificateChain: [bytes],
  algorithm: 'ecdsa',
  digest: 'sha256',
  sign: async (tbs: Buffer, digest: Buffer, digestAlgorithm: DigestAlg) => {
    void [digest, digestAlgorithm]
    return new Uint8Array(tbs.length)
  },
}
// Synchronous signers, signers that ignore some arguments and WebCrypto's ArrayBuffer results fit.
const syncExternal: ExternalSigner = { certificateChain: [bytes], algorithm: 'rsa-pkcs1v15', sign: () => buffer }
const webCryptoLike: ExternalSigner = {
  certificateChain: [bytes],
  algorithm: 'ecdsa',
  sign: (tbs) => Promise.resolve(new ArrayBuffer(tbs.length)),
}
const signPdfOptions: SignPdfOptions = { signer: p12Signer, reason: 'Approved', contentsReserve: 100 }
const signedPdf: Promise<Buffer> = signPdf(opened, signPdfOptions)
const signedExternally: Promise<Buffer> = signPdf(opened, { signer: external, signingTime: 'D:2026', field: { name: 'X' } })
signPdf(opened, { signer: syncExternal })
signPdf(opened, { signer: webCryptoLike, digest: 'sha512' })
// @ts-expect-error the signer is required
signPdf(opened, { reason: 'x' })
// @ts-expect-error the chain comes from the signer, not the options
signPdf(opened, { signer: p12Signer, certificateChain: [bytes] })
// @ts-expect-error a signer returns bytes
signPdf(opened, { signer: { certificateChain: [bytes], algorithm: 'ecdsa', sign: () => 'signature' } })
// @ts-expect-error the document is a PdfDocument
signPdf(bytes, { signer: p12Signer })

// ---- verification ------------------------------------------------------------------------------

const verifyOptions: VerifyOptions = {
  trustAnchors: [bytes],
  extraCertificates: [buffer],
  validationTime: new Date(),
}
const claimedTime: VerifyOptions = { validationTime: null }
const reportsPromise: Promise<SignatureReport[]> = opened.verifySignatures(verifyOptions)
const reportsDefault: Promise<SignatureReport[]> = opened.verifySignatures()
declare const report: SignatureReport
const acceptable: boolean = isSignatureAcceptable(report)
const acceptableLta: boolean = isSignatureAcceptable(report, 'ltaUpdates')
// @ts-expect-error: not a modification level
isSignatureAcceptable(report, 'everything')
const reportShape: Equal<
  SignatureReport,
  {
    fieldName: string | null
    kind: SignatureKind
    sigObject: ObjectRef
    subFilter: string | null
    byteRange: number[] | null
    byteRangeOk: boolean
    intact: boolean
    signatureValid: boolean
    coverage: Coverage
    signedRevision: number | null
    modification: ModificationLevel
    changedObjects: ObjectRef[]
    digestAlgorithm: string | null
    signatureAlgorithm: string | null
    signer: CertificateInfo | null
    chain: CertificateInfo[]
    trusted: boolean | null
    claimedTime: string | null
    name: string | null
    reason: string | null
    location: string | null
    contactInfo: string | null
    padesLevel: PadesLevel | null
    timestamp: TimestampInfo | null
    timestamps: TimestampInfo[]
    docmdp: number | null
    docmdpOk: boolean | null
    problems: SignatureProblem[]
    warnings: string[]
  }
> = true
const certificateShape: Equal<
  CertificateInfo,
  {
    subject: string
    issuer: string
    commonName: string | null
    serialHex: string
    notBefore: string
    notAfter: string
    sha256Hex: string
    key: KeyDescription
    keyUsage: string[]
    extKeyUsage: string[]
    isCa: boolean
    der: Buffer
  }
> = true
const coverages: Equal<Coverage, 'entireFile' | 'entireRevision' | 'contiguousBlockFromStart' | 'unclear'> = true
const modifications: Equal<ModificationLevel, 'none' | 'ltaUpdates' | 'formFilling' | 'annotations' | 'other'> = true
const kinds: Equal<SignatureKind, 'signature' | 'docTimeStamp'> = true
const padesLevels: Equal<PadesLevel, 'B-B' | 'B-T'> = true
const problemCode: ProblemCode = 'digestMismatch'
const reportProblemCode: ProblemCode | undefined = report.problems[0]?.code
const subjectText: string | undefined = report.signer?.subject
// @ts-expect-error not a problem code
const notAProblem: ProblemCode = 'somethingWrong'
// @ts-expect-error not a coverage level
const notACoverage: Coverage = 'entire'
// @ts-expect-error trust anchors are bytes
opened.verifySignatures({ trustAnchors: ['root.pem'] })

// ---- M4: timestamps (B-T), certification, visible signatures ------------------------------------

const timestampShape: Equal<
  TimestampInfo,
  {
    genTime: string
    tsa: CertificateInfo | null
    tsaName: string | null
    policy: string | null
    serialHex: string | null
    accuracyMicros: number | null
    ordering: boolean
    imprintAlgorithm: string | null
    signatureAlgorithm: string | null
    intact: boolean
    valid: boolean
    trusted: boolean | null
    problems: SignatureProblem[]
    warnings: string[]
  }
> = true
const reportTimestamp: TimestampInfo | null = report.timestamp
const genTime: string | undefined = report.timestamps[0]?.genTime
const timestampTrusted: boolean | null | undefined = report.timestamp?.trusted
// The new problem codes.
const timestampCodes: ProblemCode[] = [
  'timestampMalformed',
  'timestampImprintMismatch',
  'timestampSignatureInvalid',
  'timestampEssMismatch',
  'tsaCertificateUnsuitable',
  'tsaCertificateNotValidAtGenTime',
  'tsaNameMismatch',
  'docMdpInvalid',
  'certificationNotFirst',
  'sigDictAmbiguous',
]
const timestampCode: ErrorCode = 'E_TIMESTAMP_INVALID'
const docMdpCode: ErrorCode = 'E_DOC_MDP_FORBIDS'

const docMdpLevels: Equal<DocMdpLevel, 1 | 2 | 3> = true
const certifiedOptions: PrepareSignatureOptions = { ...minimalPrepareOptions, certify: 2, tsaReserve: 8192 }
// @ts-expect-error P is 1, 2 or 3
opened.prepareSignature({ ...minimalPrepareOptions, certify: 4 })

const appearanceFonts: Equal<AppearanceFont, 'Helvetica' | 'Helvetica-Bold'> = true
const imagePositions: Equal<ImagePosition, 'left' | 'background'> = true
const appearance: SignatureAppearanceOptions = {
  rect: [360, 40, 560, 100],
  lines: ['Approved', 'Folioxide'],
  font: 'Helvetica-Bold',
  fontSize: 9,
  image: buffer,
  imagePosition: 'background',
  borderWidth: 1,
}
const appearanceRect: SignatureAppearanceOptions = { rect: { llx: 0, lly: 0, urx: 100, ury: 50 } }
const existingField: SignatureAppearanceOptions = {}
const visibleOptions: PrepareSignatureOptions = { ...minimalPrepareOptions, appearance }
const visiblePrepared: PreparedSignature = opened.prepareSignature(visibleOptions)
// @ts-expect-error a rectangle has four numbers
const threeNumbers: SignatureAppearanceOptions = { rect: [0, 0, 100] }
// @ts-expect-error only the standard-14 Helvetica fonts
const timesFont: SignatureAppearanceOptions = { font: 'Times-Roman' }
// @ts-expect-error the image goes left or in the background
const rightImage: SignatureAppearanceOptions = { imagePosition: 'right' }
// @ts-expect-error the image is bytes
const imagePath: SignatureAppearanceOptions = { image: 'logo.jpg' }

const timestampOptions: TimestampRequestOptions = { digest: 'sha384', policy: '1.2.3.4.1', nonce: 42n }
const timestampRequest: Buffer = prepared.timestampRequest(bytes)
const timestampRequestWithOptions: Buffer = prepared.timestampRequest(buffer, timestampOptions)
const finishedBT: Buffer = prepared.finish(bytes, buffer)
const finishedBTExplicit: Buffer = prepared.finish(bytes, buffer, timestampRequest)
const finishedBTAsync: Promise<Buffer> = prepared.finishAsync(bytes, buffer, bytes)
const discarded: void = prepared.discardTimestampRequest()
// @ts-expect-error the nonce is a bigint
prepared.timestampRequest(bytes, { nonce: 'random' })
// @ts-expect-error SHA-1 is not used for imprints
prepared.timestampRequest(bytes, { digest: 'sha1' })

const syncTsa: TimestampCallback = (request: Buffer) => request
const asyncTsa: TimestampCallback = async (request) => new Uint8Array(request.length)
const webTsa: TimestampCallback = (request) => Promise.resolve(new ArrayBuffer(request.length))
const signedBT: Promise<Buffer> = signPdf(opened, {
  signer: p12Signer,
  timestamp: asyncTsa,
  timestampOptions: { nonce: 7n },
  tsaReserve: 16384,
  certify: 2,
  appearance: { rect: [360, 40, 560, 100] },
})
// @ts-expect-error a TSA returns bytes
signPdf(opened, { signer: p12Signer, timestamp: () => 'response' })
// @ts-expect-error the timestamp is a callback, not a URL
signPdf(opened, { signer: p12Signer, timestamp: 'https://tsa.example.com/' })

const verifyTsaAnchors: VerifyOptions = { trustAnchors: [bytes], timestampTrustAnchors: [buffer] }

// ---- the generated binding agrees with the facade ----------------------------------------------

// What the native addon returns is exactly what the facade declares (Diagnostic narrows `kind`
// from a string to DiagnosticKind).
const bindingPage: Equal<binding.PageInfo, PageInfo> = true
const bindingRect: Equal<binding.Rect, Rect> = true
const bindingInfo: Equal<binding.DocInfo, DocInfo> = true
const bindingTrapped: Equal<binding.Trapped, Trapped> = true
const bindingPageBox: Equal<binding.PageBox, PageBox> = true
const bindingXref: Equal<binding.XrefStyle, XrefStyle> = true
const bindingCompression: Equal<binding.StreamCompression, StreamCompression> = true
const bindingDiagnostic: binding.Diagnostic = {} as Diagnostic
// What the facade takes, the native addon takes too (dates converted to strings first).
const bindingSaveOptions: binding.SaveOptions = saveOptions
const bindingIncremental: binding.IncrementalSaveOptions = incrementalOptions
const bindingOpenOptions: binding.OpenOptions = openOptions
const bindingUpdate: binding.InfoUpdate = { ...update, creationDate: 'D:2026', modDate: null }
// Signing: the same names and shapes; the facade narrows `problems[].code` to ProblemCode and
// takes dates as `Date` too.
const bindingSigAlg: Equal<binding.SigAlg, SigAlg> = true
const bindingDigestAlg: Equal<binding.DigestAlg, DigestAlg> = true
const bindingSubFilter: Equal<binding.SubFilter, SubFilter> = true
const bindingFieldMode: Equal<binding.FieldMode, FieldMode> = true
const bindingCoverage: Equal<binding.Coverage, Coverage> = true
const bindingModification: Equal<binding.ModificationLevel, ModificationLevel> = true
const bindingKind: Equal<binding.SignatureKind, SignatureKind> = true
const bindingPades: Equal<binding.PadesLevel, PadesLevel> = true
const bindingObjectRef: Equal<binding.ObjectRef, ObjectRef> = true
const bindingKey: Equal<binding.KeyDescription, KeyDescription> = true
const bindingCertificate: Equal<binding.CertificateInfo, CertificateInfo> = true
const bindingFieldSpec: Equal<binding.SignatureFieldSpec, SignatureFieldSpec> = true
const bindingReportFields: Equal<Omit<binding.SignatureReport, 'problems'>, Omit<SignatureReport, 'problems'>> = true
const bindingReport: binding.SignatureReport = report
const bindingProblem: binding.SignatureProblem = {} as SignatureProblem
// M4: the report, its problems and its timestamps are exactly the facade's types.
const bindingReportEqual: Equal<binding.SignatureReport, SignatureReport> = true
const bindingProblemEqual: Equal<binding.SignatureProblem, SignatureProblem> = true
const bindingProblemCode: Equal<binding.ProblemCode, ProblemCode> = true
const bindingTimestamp: Equal<binding.TimestampInfo, TimestampInfo> = true
const bindingTimestampOptions: Equal<binding.TimestampRequestOptions, TimestampRequestOptions> = true
const bindingAppearanceFont: Equal<binding.AppearanceFont, AppearanceFont> = true
const bindingImagePosition: Equal<binding.ImagePosition, ImagePosition> = true
// The facade takes a rectangle as a tuple too; the native addon takes a Rect.
const bindingAppearance: binding.SignatureAppearanceOptions = { ...appearance, rect: { llx: 360, lly: 40, urx: 560, ury: 100 } }
const bindingCertified: binding.PrepareSignatureOptions = { ...certifiedOptions, appearance: undefined, signingTime: 'D:2026' }
// (The facade converts a tuple `appearance.rect` to a Rect; `bindingAppearance` checks the rest.)
const bindingPrepare: binding.PrepareSignatureOptions = {
  ...prepareOptions,
  appearance: undefined,
  signingTime: 'D:20261010120000Z',
}
const bindingVerify: binding.VerifyOptions = { ...verifyOptions, validationTime: 'D:20261010120000Z' }
const bindingSignerChain: Equal<binding.LocalSigner['certificateChain'], LocalSigner['certificateChain']> = true
const bindingSignerClose: Equal<binding.LocalSigner['close'], LocalSigner['close']> = true
const bindingSignerClosed: Equal<binding.LocalSigner['isClosed'], LocalSigner['isClosed']> = true
const bindingPreparedDigest: Equal<binding.PreparedSignature['toBeSignedDigest'], PreparedSignature['toBeSignedDigest']> = true

export {
  appearanceFonts,
  appearanceRect,
  bindingAppearance,
  bindingAppearanceFont,
  bindingCertified,
  bindingImagePosition,
  bindingProblemCode,
  bindingProblemEqual,
  bindingReportEqual,
  bindingTimestamp,
  bindingTimestampOptions,
  docMdpCode,
  docMdpLevels,
  existingField,
  finishedBT,
  finishedBTAsync,
  finishedBTExplicit,
  genTime,
  imagePath,
  imagePositions,
  reportTimestamp,
  rightImage,
  signedBT,
  syncTsa,
  threeNumbers,
  timesFont,
  timestampCode,
  timestampCodes,
  timestampRequestWithOptions,
  discarded,
  timestampShape,
  timestampTrusted,
  verifyTsaAnchors,
  visiblePrepared,
  webTsa,
  bindingCertificate,
  bindingCoverage,
  bindingDigestAlg,
  bindingFieldMode,
  bindingFieldSpec,
  bindingKey,
  bindingKind,
  bindingModification,
  bindingObjectRef,
  bindingPades,
  bindingPrepare,
  bindingPreparedDigest,
  bindingProblem,
  bindingReport,
  bindingReportFields,
  bindingSigAlg,
  bindingSignerChain,
  bindingSignerClose,
  bindingSignerClosed,
  bindingSubFilter,
  bindingVerify,
  acceptable,
  acceptableLta,
  byteRange,
  capacity,
  certificateShape,
  claimedTime,
  coverages,
  deserialized,
  digestAlgs,
  embedded,
  embeddedAsync,
  external,
  fieldModes,
  fieldSpec,
  finished,
  finishedAsync,
  isFinished,
  kinds,
  minimalPrepareOptions,
  modifications,
  notACoverage,
  notAProblem,
  padesLevels,
  pemSignerNoPassword,
  signerClosed,
  preparedAlgorithm,
  preparedAsync,
  preparedDigest,
  preparedSubFilter,
  preparedWarnings,
  problemCode,
  reportProblemCode,
  reportShape,
  reportsDefault,
  reportsPromise,
  serialized,
  sigAlgs,
  signedAsync,
  signedBytes,
  signedBytesSha384,
  signedExternally,
  signedPdf,
  signerAlgorithm,
  signerChain,
  signerDigest,
  stringTime,
  subFilters,
  subjectText,
  toBeSigned,
  toBeSignedDigest,
  toBeSignedDigestInfo,
  bindingCompression,
  bindingDiagnostic,
  bindingIncremental,
  bindingInfo,
  bindingOpenOptions,
  bindingPage,
  bindingPageBox,
  bindingRect,
  bindingSaveOptions,
  bindingSignature,
  bindingTrapped,
  bindingUpdate,
  bindingXref,
  busy,
  closeResult,
  closedCode,
  compressions,
  constructed,
  creationDate,
  custom,
  dateInput,
  disposable,
  disposeResult,
  facadeSignature,
  incremental,
  incrementalAsync,
  info,
  isClosed,
  isModified,
  kind,
  n,
  nativeMemory,
  notACode,
  notAKind,
  offset,
  openedAsync,
  openedStrict,
  page,
  pageBox,
  pageCount,
  pageShape,
  parsed,
  pdfDate,
  pdfVersion,
  rectShape,
  saved,
  savedAsync,
  savedDefault,
  someKind,
  suffix,
  syntax,
  title,
  trapped,
  trappedValues,
  v,
  xrefStyles,
}
