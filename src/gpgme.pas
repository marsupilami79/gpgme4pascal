unit gpgme;

{$mode delphi}{$H+}

interface

uses
  Classes, SysUtils;

type
  TGpgmeContext = class(TComponent)
    protected
      FLibrary: AnsiString;
      FKeys: TStringList;
      FAsciiArmor: Boolean;
      procedure SetKeys(NewKeys: TStringList); virtual;
    public
      procedure Encrypt(SrcStream, DstStream: TStream); virtual; overload;
      procedure Encrypt(SrcFile: AnsiString; DstStream: TStream); virtual; overload;
      procedure Encrypt(SrcStream: TStream; DstFile: AnsiString); virtual; overload;
      procedure Encrypt(SrcFile, DstFile: AnsiString); virtual; overload;
      constructor Create(AOwner: TComponent); override;
      destructor Destroy; override;
    published
      property LibraryLocation: AnsiString read FLibrary write FLibrary;
      property Keys: TStringList read FKeys write SetKeys;
      property AsciiArmor: Boolean read FAsciiArmor write FAsciiArmor;
  end;

implementation

uses gpgme_h;

procedure TGpgmeContext.SetKeys(NewKeys: TStringList);
begin
  FKeys.Assign(NewKeys);
end;

procedure TGpgmeContext.Encrypt(SrcStream, DstStream: TStream);
var
  context: Tgpgme_ctx_t;
  Src, Dst: Tgpgme_data_t;
  keys: TDynPgpgmeKeyArray;
  SrcAdapter, DstAdapter: TGpgmeStreamAdapter;
  x: Integer;
  Res: Tgpgme_error;
  key: Pgpgme_key;

  flags: Tgpgme_encrypt_flags_t;
begin
  if FKeys.Count = 0 then raise GpgmeError.Create('No keys were selected for the encryption operation.');
  LoadGpgme(FLibrary);

  CheckGpgmeError(gpgme_new(@context));
  try
    gpgme_set_armor(context, True);
    SetLength(Keys, FKeys.Count + 1);
    for x := 0 to FKeys.Count - 1 do begin
      Res := gpgme_get_key(context, PChar(FKeys.Strings[x]), @key, false);
      if Res.error <> 0 then begin
        if Res.errorcode = GPG_ERR_EOF
        then raise GpgmeError.Create('The Key with ID "' + FKeys.Strings[x] + '" was not found.')
        else CheckGpgmeError(Res);
      end else begin
        keys[x] := key;
      end;
    end;
    keys[FKeys.Count] := nil;

    try
      DstAdapter := TGpgmeStreamAdapter.Create(DstStream);
      try
        dst := DstAdapter.DH;
        SrcAdapter := TGpgmeStreamAdapter.Create(SrcStream);
        try
          Src := SrcAdapter.DH;
          CheckGpgmeError(gpgme_op_encrypt(context, @(keys[0]), 0, Src, Dst));

        finally
          FreeAndNil(SrcAdapter);
        end;
      finally
        FreeAndNil(DstAdapter);
      end;
    finally
      for x := 0 to Length(keys) - 1
      do if Assigned(keys[x]) then gpgme_key_release(keys[x]);
      SetLength(keys, 0);
    end;
  finally
    gpgme_release(context);
  end;
end;

procedure TGpgmeContext.Encrypt(SrcFile: AnsiString; DstStream: TStream);
var
  SrcStream: TFileStream;
begin
  SrcStream := TFileStream.Create(SrcFile, fmOpenRead or fmShareDenyWrite);
  try
    Encrypt(SrcStream, DstStream);
  finally
    FreeAndNil(SrcStream);
  end;
end;

procedure TGpgmeContext.Encrypt(SrcStream: TStream; DstFile: AnsiString);
var
  DstStream: TFileStream;
begin
  DstStream := TFileStream.Create(DstFile, fmOpenReadWrite or fmShareExclusive or fmCreate);
  try
    Encrypt(SrcStream, DstStream);
  finally
    FreeAndNil(DstStream);
  end;
end;

procedure TGpgmeContext.Encrypt(SrcFile, DstFile: AnsiString);
var
  DstStream: TFileStream;
begin
  DstStream := TFileStream.Create(DstFile, fmOpenReadWrite or fmShareExclusive or fmCreate);
  try
    Encrypt(SrcFile, DstStream);
  finally
    FreeAndNil(DstStream);
  end;
end;

constructor TGpgmeContext.Create(AOwner: TComponent);
begin
  Inherited;
  FKeys := TStringList.Create;
end;

destructor TGpgmeContext.Destroy;
begin
  if Assigned(FKeys) then FreeAndNil(FKeys);
  inherited;
end;

end.

