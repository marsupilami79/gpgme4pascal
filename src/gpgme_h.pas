unit gpgme_h;

{$mode delphi}{$H+}

interface

uses
  Classes, SysUtils, DynLibs{$ifdef fpc}{$ifdef unix}, unixtype{$ifend}{$ifend};

type
  GpgmeError = class(Exception);

  //GPGME consts
const
  //enum gpgme_protocol_t:
  GPGME_PROTOCOL_OpenPGP = 0;
  GPGME_PROTOCOL_CMS     = 1;
  GPGME_PROTOCOL_GPGCONF = 2;
  GPGME_PROTOCOL_ASSUAN  = 3;
  GPGME_PROTOCOL_UNKNOWN = 255;

  GPGME_INCLUDE_CERTS_DEFAULT: Integer = -256;

  //enum gpgme_validity_t
  GPGME_VALIDITY_UNKNOWN = 0;
  GPGME_VALIDITY_UNDEFINED = 1;
  GPGME_VALIDITY_NEVER = 2;
  GPGME_VALIDITY_MARGINAL = 3;
  GPGME_VALIDITY_FULL = 4;
  GPGME_VALIDITY_ULTIMATE = 5;

  //enum gpgme_pubkey_algo_t
  GPGME_PK_RSA = 1;
  GPGME_PK_RSA_E = 2;
  GPGME_PK_RSA_S = 3;
  GPGME_PK_ELG_E = 16;
  GPGME_PK_DSA = 17;
  GPGME_PK_ELG = 20;

  //enum gpgme_encrypt_flags_t
  GPGME_ENCRYPT_ALWAYS_TRUST = 1;
  GPGME_ENCRYPT_NO_ENCRYPT_TO = 2;
  GPGME_ENCRYPT_PREPARE = 4;
  GPGME_ENCRYPT_EXPECT_SIGN = 8;

  //available keylist mode flags
  GPGME_KEYLIST_MODE_LOCAL = 1;
  GPGME_KEYLIST_MODE_EXTERN = 2;
  GPGME_KEYLIST_MODE_SIGS = 4;
  GPGME_KEYLIST_MODE_SIG_NOTATIONS = 8;
  GPGME_KEYLIST_MODE_EPHEMERAL = 128;
  GPGME_KEYLIST_MODE_VALIDATE = 256;

  //error codes:
  GPG_ERR_EOF = 16383;

type
  // compatibility declarations
  // ssize_t also exists on Windows. See https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751%28v=vs.85%29.aspx
  {$ifdef fpc}
    {$ifdef windows}
      {$ifdef cpu64}
        ssize_t = Int64;
      {$else}
        ssize_t = Integer;
      {$ifend cpu64}
      off_t = Integer;
      clong = LongInt;
    {$ifend windows}
  {$ifend fpc}


  //GPGME types
  //GPG redifined types
  Tgpg_error = packed record
    case boolean of
      true: (
        error: Cardinal
      );
      false: (
        errorcode: Word;
        errorsource: Word;
      );
  end;
  Tgpgme_error = Tgpg_error;

  //other redefinitions:
  Tgpgme_ssize_t = ssize_t;

  //types:
  Tgpgme_data_t = Pointer;
  Pgpgme_data_t = ^Tgpgme_data_t;
  //Tgpgme_off_t = Integer;
  Tgpgme_sig_notation_flags_t = Cardinal;
  Tgpgme_ctx_t = Pointer;
  Pgpgme_ctx_t = ^Tgpgme_ctx_t;
  Tgpgme_keylist_mode_t = Cardinal;
  Tgpgme_encrypt_flags_t = Cardinal;

  //Enums:
  Tgpgme_protocol_t = Integer;
  Tgpgme_validity_t = Integer;
  Tgpgme_pubkey_algo_t = Integer;

  //callback data buffer callback functions
  Tgpgme_data_read_cb_t = function(handle: Pointer; buffer: Pointer; size: size_t): Tgpgme_ssize_t; cdecl;
  Tgpgme_data_write_cb_t = function(handle: Pointer; buffer: Pointer; size: size_t): Tgpgme_ssize_t; cdecl;
  Tgpgme_data_seek_cb_t = function(handle: Pointer; offset: off_t; whence: Integer): off_t; cdecl;
  Tgpgme_data_release_cb_t = procedure(handle: pointer); cdecl;

  //Records:
  Tgpgme_data_cbs = {$ifndef cpu64}packed{$ifend cpu64} record
    read: Tgpgme_data_read_cb_t;
    write: Tgpgme_data_write_cb_t;
    seek: Tgpgme_data_seek_cb_t;
    release: Tgpgme_data_release_cb_t;
  end;
  Pgpgme_data_cbs = ^Tgpgme_data_cbs;

  Pgpgme_engine_info = ^Tgpgme_engine_info;
  Tgpgme_engine_info = {$ifndef cpu64}packed{$ifend cpu64} record
    next: Pgpgme_engine_info;
    protocol: Tgpgme_protocol_t;
    file_name: PAnsiChar;
    version: PAnsiChar;
    req_version: PAnsiChar;
    home_dir: PAnsiChar;
  end;

  Pgpgme_sig_notation = ^Tgpgme_sig_notation;
  Tgpgme_sig_notation = {$ifndef cpu64}packed{$ifend cpu64} record
    next: Pgpgme_sig_notation;
    name: PAnsiChar;
    value: PAnsiChar;
    name_len: Integer;
    value_len: Integer;
    flags: Tgpgme_sig_notation_flags_t;
    (*
    human_readable: LongBool;
    critical: LongBool;
    _unused: Cardinal;
    *)
    _flags: Cardinal;
  end;

  TKeyID = packed record
    _keyid_1: byte;
    _keyid_2: byte;
    _keyid_3: byte;
    _keyid_4: byte;
    _keyid_5: byte;
    _keyid_6: byte;
    _keyid_7: byte;
    _keyid_8: byte;
    _keyid_9: byte;
    _keyid_10: byte;
    _keyid_11: byte;
    _keyid_12: byte;
    _keyid_13: byte;
    _keyid_14: byte;
    _keyid_15: byte;
    _keyid_16: byte;
    _keyid_17: byte;
  end;

  Pgpgme_key_sig = ^Tgpgme_key_sig;
  Tgpgme_key_sig = {$ifndef cpu64}packed{$ifend cpu64} record
    next: Pgpgme_key_sig;
    _flags: Cardinal;
    pubkey_algo: Tgpgme_pubkey_algo_t;
    keyid: PAnsiChar;
    _keyid: TKeyID;
    timestamp: clong;
    expires: clong;
    status: Tgpgme_error;
    _obsolete_class: Cardinal;
    uid: PAnsiChar;
    name: PAnsiChar;
    email: PAnsiChar;
    comment: PAnsiChar;
    sig_class: Cardinal;
    notations: Pgpgme_sig_notation;
    _last_notation: Pgpgme_sig_notation;
  end;

  Pgpgme_user_id = ^Tgpgme_user_id;
  Tgpgme_user_id = {$ifndef cpu64}packed{$ifend cpu64} record
    next: Pgpgme_user_id;
    _flags: Cardinal;
    validity: Tgpgme_validity_t;
    uid: PAnsiChar;
    name: PAnsiChar;
    email: PAnsiChar;
    comment: PAnsiChar;
    signatures: Pgpgme_key_sig;
    _last_keysig: Pgpgme_key_sig;
  end;

  Pgpgme_subkey = ^Tgpgme_subkey;
  Tgpgme_subkey = {$ifndef cpu64}packed{$ifend cpu64} record
    next: Pgpgme_subkey;
    (*
    revoked: LongBool;
    expired: LongBool;
    disabled: LongBool;
    invalid: LongBool;
    can_encrypt: LongBool;
    can_sign: LongBool;
    can_certify: LongBool;
    secret: LongBool;
    can_authenticate: LongBool;
    is_qualified: LongBool;
    is_cardkey: LongBool;
    _unused: Cardinal;
    *)
    _flags: Cardinal;
    pubkey_algo: Tgpgme_pubkey_algo_t;
    length: Cardinal;
    keyid: PAnsiChar;
    _keyyid: TKeyID;
    fpr: PAnsiChar;
    timestamp: clong;
    expires: clong;
    card_number: PAnsiChar;
    // properties for accessing the flags
    private
      function getRevoked: boolean;
      function getExpired: boolean;
      function getDisabled: boolean;
      function getInvalid: boolean;
      function getCanEncrypt: boolean;
      function getCanSign: boolean;
      function getCanCertify: boolean;
      function getSecret: boolean;
      function getCanAuthenticate: boolean;
      function getIsQualified: boolean;
      function getIsCardkey: boolean;
    public
      property revoked: boolean read getRevoked;
      property expired: boolean read getExpired;
      property disabled: boolean read getDisabled;
      property invalid: boolean read getInvalid;
      property can_encrypt: boolean read getCanEncrypt;
      property can_sign: boolean read getCanSign;
      property can_certify: boolean read getCanCertify;
      property secret: boolean read getSecret;
      property can_authenticate: boolean read getCanAuthenticate;
      property is_qualified: boolean read getIsQualified;
      property is_cardkey: boolean read getIsCardkey;
  end;

  PPgpgme_key = ^Pgpgme_key;
  Pgpgme_key = ^Tgpgme_key;
  Tgpgme_key = {$ifndef cpu64}packed{$ifend cpu64} record
    _refs: Cardinal;
{
    revoked: LongBool;
    expired: LongBool;
    disabled: LongBool;
    invalid: LongBool;
    can_encrypt: LongBool;
    can_sign: LongBool;
    can_certify: LongBool;
    secret: LongBool;
    can_authenticate: LongBool;
    is_qualified: LongBool;
    _unused: LongBool;
}
    flags: Cardinal;
    protocol: Tgpgme_protocol_t;
    issuer_serial: PAnsiChar;
    issuer_name: PAnsiChar;
    chain_id: PAnsiChar;
    owner_trust: Tgpgme_validity_t;
    subkeys: Pgpgme_subkey;
    uids: Pgpgme_user_id;
    _last_subkey: Pgpgme_subkey;
    _last_uid: Pgpgme_user_id;
    keylist_mode: Tgpgme_keylist_mode_t;
  end;
  TDynPgpgmeKeyArray = array of Pgpgme_key;

  //GPGME functions
  Tgpgme_check_version = function(required_version: PAnsiChar): PAnsiChar; cdecl;
  Tgpgme_get_protocol_name = function(protocol: Tgpgme_protocol_t):PAnsiChar; cdecl;
  Tgpgme_set_locale = function(ctx: Tgpgme_ctx_t; category: Integer; value: PAnsiChar): Tgpgme_error ;cdecl;
  Tgpgme_new = function(ctx: Pgpgme_ctx_t): Tgpgme_error; cdecl;
  Tgpgme_release = procedure(ctx: Tgpgme_ctx_t); cdecl;
  Tgpgme_set_protocol = function(ctx: Tgpgme_ctx_t; proto: Tgpgme_protocol_t): Tgpgme_error; cdecl;
  Tgpgme_get_protocol = function(ctx: Tgpgme_ctx_t): Tgpgme_protocol_t; cdecl;
  Tgpgme_ctx_get_engine_info = function(ctx: Tgpgme_ctx_t): Pgpgme_engine_info; cdecl;
  Tgpgme_ctx_set_engine_info = function(ctx: Tgpgme_ctx_t; proto: Tgpgme_protocol_t; const file_name: PAnsiChar; const home_dir: PAnsiChar): Tgpgme_error; cdecl;
  Tgpgme_set_armor = procedure(ctx: Tgpgme_ctx_t; yes: LongBool); cdecl;
  Tgpgme_get_armor = function(ctx: Tgpgme_ctx_t): LongBool; cdecl;
  Tgpgme_set_textmode = procedure(ctx: Tgpgme_ctx_t; yes: LongBool); cdecl;
  Tgpgme_get_textmode = function(ctx: Tgpgme_ctx_t): LongBool; cdecl;
  Tgpgme_set_include_certs = procedure(ctx: Tgpgme_ctx_t; nr_of_certs: Integer); cdecl;
  Tgpgme_get_include_certs = function(ctx: Tgpgme_ctx_t ): Integer; cdecl;
  Tgpgme_data_new_from_fd = function(dh: Pgpgme_data_t; fd: THandle): Tgpgme_error; cdecl;
  Tgpgme_op_keylist_start = function(ctx: Tgpgme_ctx_t; const pattern: PAnsiChar; secret_only: LongBool): Tgpgme_error; cdecl;
  Tgpgme_op_keylist_next = function(ctx: Tgpgme_ctx_t; r_key: PPgpgme_key): Tgpgme_error; cdecl;
  Tgpgme_op_keylist_end = function(ctx: Tgpgme_ctx_t): Tgpgme_error; cdecl;
  Tgpgme_set_engine_info = function(proto: Tgpgme_protocol_t; const file_name: PAnsiChar; const home_dir: PAnsiChar): Tgpgme_error; cdecl;
  Tgpgme_get_key = function(ctx: Tgpgme_ctx_t; const fpr: PAnsiChar; r_key: PPgpgme_key; secret: LongBool): Tgpgme_error; cdecl;
  Tgpgme_op_encrypt = function(ctx: Tgpgme_ctx_t; recp: PPgpgme_key; flags: Tgpgme_encrypt_flags_t; plain: Tgpgme_data_t; cipher: Tgpgme_data_t): Tgpgme_error; cdecl;
  Tgpgme_strerror = function(err: Tgpgme_error): PAnsiChar; cdecl;
  Tgpgme_data_new_from_file = function(dh: Pgpgme_data_t; const filename: PAnsiChar; copy: LongBool): Tgpgme_error; cdecl;
  Tgpgme_data_new = function(dh: Pgpgme_data_t): Tgpgme_error; cdecl;
  Tgpgme_data_new_from_mem = function(dh: Pgpgme_data_t; const buffer: PChar; size: size_t; copy: LongBool): Tgpgme_error; cdecl;
  Tgpgme_data_new_from_cbs = function(dh: Pgpgme_data_t; cbs: Pgpgme_data_cbs; handle: Pointer): Tgpgme_error; cdecl;
  Tgpgme_data_release = procedure(dh: Tgpgme_data_t); cdecl;
  Tgpgme_key_release = procedure(key: Pgpgme_key); cdecl;

  TGpgmeStreamAdapter = class
  protected
    FStream: TStream;
    FDH: Tgpgme_data_t;
    FCallbacks: Tgpgme_data_cbs;
    function Read(buffer: Pointer; Size: Integer): Integer;
    function Write(buffer: Pointer; Size: Integer): Integer;
    function Seek(offset: Integer; Whence: TSeekOrigin): Integer;
    procedure Release;
    function GetDH: Tgpgme_data_t;
  public
    constructor Create(Stream: TStream);
    destructor Destroy; override;
    property DH: Tgpgme_data_t read GetDH;
  end;

var
  gpgme_check_version: Tgpgme_check_version;
  gpgme_get_protocol_name: Tgpgme_get_protocol_name;
  gpgme_set_locale: TGpgme_set_locale;
  gpgme_new: Tgpgme_new;
  gpgme_release: Tgpgme_release;
  gpgme_set_protocol: Tgpgme_set_protocol;
  gpgme_get_protocol: Tgpgme_get_protocol;
  gpgme_ctx_get_engine_info: Tgpgme_ctx_get_engine_info;
  gpgme_ctx_set_engine_info: Tgpgme_ctx_set_engine_info;
  gpgme_set_armor: Tgpgme_set_armor;
  gpgme_get_armor: Tgpgme_get_armor;
  gpgme_set_textmode: Tgpgme_set_textmode;
  gpgme_get_textmode: Tgpgme_get_textmode;
  gpgme_set_include_certs: Tgpgme_set_include_certs;
  gpgme_get_include_certs: Tgpgme_get_include_certs;
  gpgme_data_new_from_fd: Tgpgme_data_new_from_fd;
  gpgme_data_release: Tgpgme_data_release;
  gpgme_op_keylist_start: Tgpgme_op_keylist_start;
  gpgme_op_keylist_next: Tgpgme_op_keylist_next;
  gpgme_op_keylist_end: Tgpgme_op_keylist_end;
  gpgme_set_engine_info: Tgpgme_set_engine_info;
  gpgme_get_key: Tgpgme_get_key;
  gpgme_op_encrypt: Tgpgme_op_encrypt;
  gpgme_strerror: Tgpgme_strerror;
  gpgme_data_new_from_file: Tgpgme_data_new_from_file;
  gpgme_data_new: Tgpgme_data_new;
  gpgme_data_new_from_mem: Tgpgme_data_new_from_mem;
  gpgme_data_new_from_cbs: Tgpgme_data_new_from_cbs;
  gpgme_key_release: Tgpgme_key_release;

procedure LoadGpgme(LibraryName: String);
procedure CheckGpgmeError(Error: Tgpgme_error);

implementation

var
  LibHandle: TLibHandle;
  LibVersion: String;

function InitFunction(Name: String): Pointer;
begin
  Result := GetProcAddress(LibHandle, Name);
  if not Assigned(Result) then raise GpgmeError.Create('could not find function ' + Name + ' in GPGME library.');
end;

procedure init_gpgme;
type
  Tsetlocale = function(category: integer; locale: PAnsiChar): PAnsiChar; cdecl;
const
  LC_CTYPE    = 0;  { character classification (unsupported) }
  LC_COLLATE  = 1;  { the locale's collation table (unsupported) }
  LC_NUMERIC  = 2;  { the numeric part of struct lconv }
  LC_MONETARY = 3;  { the monetary part of struct lconv }
  LC_TIME     = 4;  { the time and date part of struct lconv }
  LC_MESSAGES = 5;  { new starting in NetWare v4.11 (unsupported) }
  LC_ALL      = 6;
var
  setlocale: TSetLocale;
  LibcHandle: TLibHandle;
  Version: PAnsiChar;
begin
  {$IFDEF WINDOWS}
  LibcHandle := LoadLibrary('msvcrt.dll');
  {$ELSE}
  LibcHandle := LoadLibrary('libc.so.6');
  {$IFEND}
  if LibHandle = 0 then raise GpgmeError.Create('could not load C library');
  try
    setlocale := GetProcAddress(LibcHandle, 'setlocale');
    if not assigned(setlocale) then raise GpgmeError.Create('could not import the function setlocale from the C library');
    { Initialize the locale environment.  }
    Version := gpgme_check_version(nil);
    if not Assigned(Version) then raise GpgmeError.Create('could not initialize GPGME');
    LibVersion := Version;
    gpgme_set_locale(nil, LC_CTYPE, setlocale (LC_CTYPE, nil));
    gpgme_set_locale(nil, LC_MESSAGES, setlocale (LC_MESSAGES, nil));
  finally
    FreeLibrary(LibcHandle);
  end;
end;


procedure LoadGpgme(LibraryName: String);
var
  CurrentDir: String;
  LibDir: String;
begin
  if LibHandle <> 0 then Exit;

  CurrentDir := GetCurrentDir;
  LibDir := ExtractFileDir(LibraryName);

  if LibDir <> '' then ChDir(LibDir);
  try
    LibHandle := LoadLibrary(LibraryName);
  finally
    ChDir(CurrentDir);
  end;

  if LibHandle = 0 then raise GpgmeError.Create('Could not load GPGME library ' + LibraryName);
  gpgme_check_version := InitFunction('gpgme_check_version');
  gpgme_set_locale := InitFunction('gpgme_set_locale');
  init_gpgme;
  gpgme_get_protocol_name := InitFunction('gpgme_get_protocol_name');
  gpgme_new := InitFunction('gpgme_new');
  gpgme_release := InitFunction('gpgme_release');
  gpgme_set_protocol := InitFunction('gpgme_set_protocol');
  gpgme_get_protocol := InitFunction('gpgme_get_protocol');
  gpgme_ctx_get_engine_info := InitFunction('gpgme_ctx_get_engine_info');
  gpgme_ctx_set_engine_info := InitFunction('gpgme_ctx_set_engine_info');
  gpgme_set_armor := InitFunction('gpgme_set_armor');
  gpgme_get_armor := InitFunction('gpgme_get_armor');
  gpgme_set_textmode := InitFunction('gpgme_set_textmode');
  gpgme_get_textmode := InitFunction('gpgme_get_textmode');
  gpgme_set_include_certs := InitFunction('gpgme_set_include_certs');
  gpgme_get_include_certs := InitFunction('gpgme_get_include_certs');
  gpgme_data_new_from_fd := InitFunction('gpgme_data_new_from_fd');
  gpgme_data_release := InitFunction('gpgme_data_release');
  gpgme_op_keylist_start := InitFunction('gpgme_op_keylist_start');
  gpgme_op_keylist_next := InitFunction('gpgme_op_keylist_next');
  gpgme_op_keylist_end := InitFunction('gpgme_op_keylist_end');
  gpgme_set_engine_info := InitFunction('gpgme_set_engine_info');
  gpgme_get_key := InitFunction('gpgme_get_key');
  gpgme_op_encrypt := InitFunction('gpgme_op_encrypt');
  gpgme_strerror := InitFunction('gpgme_strerror');
  gpgme_data_new_from_file := InitFunction('gpgme_data_new_from_file');
  gpgme_data_new := InitFunction('gpgme_data_new');
  gpgme_data_new_from_mem := InitFunction('gpgme_data_new_from_mem');
  gpgme_data_new_from_cbs := InitFunction('gpgme_data_new_from_cbs');
  gpgme_key_release := InitFunction('gpgme_key_release');
end;

procedure CheckGpgmeError(Error: Tgpgme_error);
begin
  if Error.error <> 0 then begin
    raise GpgmeError.Create(gpgme_strerror(Error));
  end;
end;

{ --- Callback Stuff --- }

function gpgme_data_read_cb(handle: Pointer; buffer: Pointer; size: size_t): Tgpgme_ssize_t; cdecl;
begin
  try
    Result := TGpgmeStreamAdapter(handle).Read(buffer, size);
  except
    Result := -1;
  end;
end;

function gpgme_data_write_cb(handle: Pointer; buffer: Pointer; size: size_t): Tgpgme_ssize_t; cdecl;
begin
  try
    Result := TGpgmeStreamAdapter(handle).Write(buffer, size);
  except
    Result := -1;
  end;
end;

function gpgme_data_seek_cb(handle: Pointer; offset: off_t; whence: Integer): off_t; cdecl;
var
  Origin: TSeekOrigin;
begin
  try
    if (whence >= 0) and (whence <=2) then begin
      case whence of
        0: Origin := soBeginning;
        1: Origin := soCurrent;
        2: Origin := soEnd;
      end;
      Result := TGpgmeStreamAdapter(handle).Seek(offset, Origin);
    end else begin
      Result := -1;
    end;
  except
    Result := -1;
  end;
end;

procedure gpgme_data_release_cb(handle: Pointer); cdecl;
begin
  try
    TGpgmeStreamAdapter(handle).Release;
  except
    // do nothing
  end;
end;

{ --- TGpgmeStreamAdapter --- }

function TGpgmeStreamAdapter.Read(buffer: Pointer; Size: Integer): Integer;
begin
  Result := FStream.Read(buffer^, Size);
end;

function TGpgmeStreamAdapter.Write(buffer: Pointer; Size: Integer): Integer;
begin
  result := FStream.Write(buffer^, Size);
end;

function TGpgmeStreamAdapter.Seek(offset: Integer; Whence: TSeekOrigin): Integer;
begin
  Result := FStream.Seek(offset, Whence);
end;

procedure TGpgmeStreamAdapter.Release;
begin
  FDH := nil;
end;

function TGpgmeStreamAdapter.GetDH: Tgpgme_data_t;
begin
  if Assigned(FDH) then begin
    Result := FDH;
  end else begin
    CheckGpgmeError(gpgme_data_new_from_cbs(@FDH, @FCallbacks, Pointer(Self)));
    Result := FDH;
  end;
end;

constructor TGpgmeStreamAdapter.Create(Stream: TStream);
begin
  inherited Create;
  FDH := nil;
  FCallbacks.read := gpgme_data_read_cb;
  FCallbacks.write := gpgme_data_write_cb;
  FCallbacks.seek := gpgme_data_seek_cb;
  FCallbacks.release := gpgme_data_release_cb;
  FStream := Stream;
end;

destructor TGpgmeStreamAdapter.Destroy;
begin
  if Assigned(FDH) then gpgme_data_release(FDH);
  inherited;
end;

{ --- Tgpgme_subkey --- }

function Tgpgme_subkey.getRevoked: boolean;
begin
  Result := LongBool(_flags and 1);
end;

function Tgpgme_subkey.getExpired: boolean;
begin
  Result := LongBool(_flags and (1 shl 1));
end;

function Tgpgme_subkey.getDisabled: boolean;
begin
  Result := LongBool(_flags and (1 shl 2));
end;

function Tgpgme_subkey.getInvalid: boolean;
begin
  Result := LongBool(_flags and (1 shl 3));
end;

function Tgpgme_subkey.getCanEncrypt: boolean;
begin
  Result := LongBool(_flags and (1 shl 4));
end;

function Tgpgme_subkey.getCanSign: boolean;
begin
  Result := LongBool(_flags and (1 shl 5));
end;

function Tgpgme_subkey.getCanCertify: boolean;
begin
  Result := LongBool(_flags and (1 shl 6));
end;

function Tgpgme_subkey.getSecret: boolean;
begin
  Result := LongBool(_flags and (1 shl 7));
end;

function Tgpgme_subkey.getCanAuthenticate: boolean;
begin
  Result := LongBool(_flags and (1 shl 8));
end;

function Tgpgme_subkey.getIsQualified: boolean;
begin
  Result := LongBool(_flags and (1 shl 9));
end;

function Tgpgme_subkey.getIsCardkey: boolean;
begin
  Result := LongBool(_flags and (1 shl 10));
end;

initialization
  LibHandle := 0;

finalization
  if LibHandle <> 0 then FreeLibrary(LibHandle);

end.

