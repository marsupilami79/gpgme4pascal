unit FormMain;

{$mode delphi}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls;

type

  { TForm1 }

  TForm1 = class(TForm)
    BrowseBtn: TButton;
    ClearTextEdt: TEdit;
    GpgmeLibOD: TOpenDialog;
    Label1: TLabel;
    encryptWithObjectBtn: TButton;
    encryptWithHeadersBtn: TButton;
    listKeysBtn: TButton;
    LogM: TMemo;
    GpgmeLibEdt: TEdit;
    GpgKeyEdt: TEdit;
    Label2: TLabel;
    Label3: TLabel;
    procedure BrowseBtnClick(Sender: TObject);
    procedure listKeysBtnClick(Sender: TObject);
    procedure encryptWithObjectBtnClick(Sender: TObject);
    procedure encryptWithHeadersBtnClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1: TForm1;

implementation

uses gpgme, gpgme_h;

{$R *.lfm}

{ TForm1 }

procedure TForm1.listKeysBtnClick(Sender: TObject);
var
  context: Tgpgme_ctx_t;
  y: Tgpgme_error;
  info: Pgpgme_engine_info;
  key: Pgpgme_key;
  uid: Pgpgme_user_id;
  subkey: Pgpgme_subkey;
  zeile: String;
  temp: String;
begin
  zeile := '';
  LogM.Clear;
  LoadGpgme(GpgmeLibEdt.Text);
  y := gpgme_new(@context);
  if y.error <> 0 then raise Exception.Create('cannot create context');
  info := gpgme_ctx_get_engine_info(context);
  if not assigned(info) then raise Exception.Create('could not get engine info');
  LogM.Append(gpgme_get_protocol_name(info.protocol) + ' ' + info.version + ' ' + info.file_name + ' ' + info.home_dir);

  y := gpgme_op_keylist_start(context, nil, false);
  CheckGpgmeError(y);
  try
    y := gpgme_op_keylist_next(context, @key);
    while y.error = 0 do begin
      uid := key.uids;
      while assigned(uid) do begin
        if zeile <> '' then Zeile := Zeile + '; ';
        if Assigned(uid.uid) then zeile := uid.uid else zeile := 'unknown UID';
        zeile := zeile + ': ';
        if Assigned(uid.name) then temp := uid.name else temp := 'unknowm name';
        zeile := zeile + temp;
        zeile := zeile + ' (';
        if assigned(uid.comment) then temp := uid.comment else temp := '';
        zeile := zeile + temp;
        zeile := zeile + ') ';
        if Assigned(uid.email) then temp := uid.email else temp := '';
        zeile := zeile + temp;
        uid := uid.next;
      end;
      LogM.Lines.Append(zeile);

      LogM.Lines.Append('  ownertrust: ' + IntToStr(key.owner_trust));

      subkey := key.subkeys;
      while assigned(subkey) do begin
        zeile := '    Key ID: ' + subkey.keyid;
        LogM.Append(Zeile);
        zeile := '      can encrypt: ' + BoolToStr(subkey.can_encrypt, true);
        LogM.Append(zeile);
        zeile := '      can sign: ' + BoolToStr(subkey.can_sign, true);
        LogM.Append(zeile);
        subkey := subkey.next;
      end;

      y := gpgme_op_keylist_next(context, @key);
      Application.ProcessMessages;
    end;
    //y := y and ($FFFF);
    if y.errorcode <> GPG_ERR_EOF then raise Exception.Create('cannot finish listing the keys');
  finally
    y := gpgme_op_keylist_end(context);
    if y.error <> 0 then raise Exception.Create('error when closing down key listing operation');
  end;

  gpgme_release(context);
end;

procedure TForm1.encryptWithObjectBtnClick(Sender: TObject);
var
  Src, Dst: TStringStream;
  gpgme: TGpgmeContext;
begin
  try
    Src := TStringStream.Create(ClearTextEdt.Text);
    Dst := TStringStream.Create('');
    gpgme := TGpgmeContext.Create(nil);
    gpgme.LibraryLocation := GpgmeLibEdt.Text;
    gpgme.AsciiArmor := true;
    gpgme.Keys.Add(GpgKeyEdt.Text);
    gpgme.Encrypt(Src, Dst);
    LogM.Lines.Text :=Dst.DataString;
  finally
    if Assigned(gpgme) then FreeAndNil(gpgme);
    if assigned(dst) then FreeAndNil(dst);
    if Assigned(src) then FreeAndNil(src);
  end;
end;

procedure TForm1.encryptWithHeadersBtnClick(Sender: TObject);
var
  context: Tgpgme_ctx_t;
  Src, Dst: Tgpgme_data_t;
  key: Pgpgme_key;
  keys: TDynPgpgmeKeyArray;
  Adapter: TGpgmeStreamAdapter;
  DstMem: TStringStream;
begin
  LoadGpgme(GpgmeLibEdt.Text);
  CheckGpgmeError(gpgme_new(@context));
  try
    gpgme_set_armor(context, true);

    CheckGpgmeError(gpgme_get_key(context, PChar(GpgKeyEdt.Text), @key, false));
    try
      SetLength(Keys, 2);
      keys[0] := key;
      keys[1] := nil;

      CheckGpgmeError(gpgme_data_new_from_mem(@Src, PAnsiChar(ClearTextEdt.Text), length(ClearTextEdt.Text), true));

      DstMem := TStringStream.Create('');
      try
        Adapter := TGpgmeStreamAdapter.Create(DstMem);
        try
          dst := Adapter.DH;
          CheckGpgmeError(gpgme_op_encrypt(context, @(keys[0]), 0, Src, Dst));
        finally
          FreeAndNil(Adapter);
        end;
        LogM.Lines.Text := DstMem.DataString;
      finally
        FreeAndNil(DstMem);
      end;
    finally
      gpgme_key_release(key);
    end;
  finally
    gpgme_release(context);
  end;
end;

procedure TForm1.BrowseBtnClick(Sender: TObject);
begin
  GpgmeLibOD.FileName := GpgmeLibEdt.Text;
  if GpgmeLibOD.Execute then GpgmeLibEdt.Text := GpgmeLibOD.FileName;
end;


end.

