unit gpgme;

{$mode delphi}{$H+}

interface

uses
  Classes,SysUtils,gpgme_h,BufDataset,db,dialogs,strings;
type

  { TGpgme }

  TGpgme = class(Tobject)
  private
      FCryptopath: string;
      FLibrary: AnsiString;
      Fhomedir:string;
      FKeys: TStringList;
      FAsciiArmor: Boolean;
      FPassPhrase:string;
      FGpgmeVersion:string;
      fproc:Tgpgme_passphrase_cb_t;
      procedure SetKeys(NewKeys: TStringList); virtual;
    public
      function GetContext: Tgpgme_ctx_t;
      procedure ImportKey(keydata:string);
      procedure FreeContext(Context:Tgpgme_ctx_t);
      function ListKeys: string;
      Function ListKeysDS:TMemoryStream;
      function GetEngineInfo: string;
      procedure Decrypt(SrcStream, DstStream: TStream);
      procedure Encrypt(SrcStream, DstStream: TStream); virtual; overload;
      procedure Encrypt(SrcFile: AnsiString; DstStream: TStream); virtual; overload;
      procedure Encrypt(SrcStream: TStream; DstFile: AnsiString); virtual; overload;
      procedure Encrypt(SrcFile, DstFile: AnsiString); virtual; overload;
      constructor Create(libpath:string);overload;
      destructor Destroy;override;
    published
      property LibraryLocation: AnsiString read FLibrary;
      property Keys: TStringList read FKeys write SetKeys;
      property AsciiArmor: Boolean read FAsciiArmor write FAsciiArmor;
      property Homedir:string read Fhomedir;
      Property Cryptopath:string read FCryptopath;
      Property PassPhrase:string read FPassPhrase write FPassPhrase;
      property GPGMEVersion:string read FGpgmeVersion;
  end;

implementation

procedure TGpgme.SetKeys(NewKeys: TStringList);
begin
     FKeys.Assign(NewKeys);
end;

function TGpgme.GetContext():Tgpgme_ctx_t;
var
   y: Tgpgme_error;
begin
     CheckGpgmeError(gpgme_new(@result));
     //Set the engine info, we wantto use the home dir in the app directory and the gpg.exe in app dir
     y:= gpgme_ctx_set_engine_info(result,GPGME_PROTOCOL_OpenPGP,pchar(FCryptopath),pchar(Fhomedir));
     CheckGpgmeError(y);
end;

procedure TGpgme.ImportKey(keydata: string);
var
   err: Tgpgme_error;
   context: Tgpgme_ctx_t;
   keysource: TGpgmeStreamAdapter;
   keydatastream:tstringstream;
   iresult: pgpgme_import_result_t;
   istatus:pgpgme_import_status_t;
   sig:pchar;
begin
     keydatastream:=TStringStream.Create(keydata);
     keydatastream.Position:=0;
     keysource:=TGpgmeStreamAdapter.Create(keydatastream);
     context:=GetContext;
     try
        err:=gpgme_op_import(context,keysource.DH);
        CheckGpgmeError(err);
        iresult:= gpgme_op_import_result(context);
        istatus:=iresult.imports;
     //  sig:=istatus.fpr ;
     //  showmessage(string(sig));
     //  CheckGpgmeError(istatus.result);
     finally
        FreeContext(context);
        keysource.Free;
        keydatastream.free;
     end;
end;

procedure TGpgme.FreeContext(Context: Tgpgme_ctx_t);

begin
     gpgme_release(context);
     Context:=nil;
end;

function TGpgme.ListKeysDS: TMemoryStream;
var
   DS:TBufDataset;
   err: Tgpgme_error;
   context: Tgpgme_ctx_t;
   key: Pgpgme_key;
   subkey: Pgpgme_subkey;
   uid: Pgpgme_user_id;
begin
     result:=TMemoryStream.create;
     DS:=TBufDataset.Create(nil);
     ds.FieldDefs.Add('UserID',TFieldType.ftString,100);
     ds.FieldDefs.Add('Name',TFieldType.ftString,100);
     ds.FieldDefs.Add('comment',TFieldType.ftString,100);
     ds.FieldDefs.Add('email',TFieldType.ftString,100);
     ds.FieldDefs.add('OwnerTrust',ftInteger);
     ds.FieldDefs.Add('KeyID',TFieldType.ftString,100);
     ds.FieldDefs.Add('CanEncrypt',TFieldType.ftBoolean);
     ds.FieldDefs.Add('CanSign',TFieldType.ftBoolean);
     ds.CreateDataset;
     ds.Open;
     context:=GetContext;
     err := gpgme_op_keylist_start(context, nil, false);
     CheckGpgmeError(err);
     try
        err := gpgme_op_keylist_next(context, @key);

        while err.error = 0 do
              begin
                    ds.insert;
                   uid := key.uids;
                   while assigned(uid) do
                   begin
                        ds.FieldByName('UserID').AsString:=uid.uid;
                        ds.FieldByName('Name').AsString:=uid.name;
                        ds.FieldByName('Comment').AsString:=uid.comment;
                        ds.FieldByName('email').AsString:= uid.email;
                        uid := uid.next;
                   end;
                  ds.FieldByName('OwnerTrust').AsInteger:=key.owner_trust;
                  subkey := key.subkeys;
                   while assigned(subkey) do
                         begin
                              ds.FieldByName('KeyID').AsString:= subkey.keyid;
                              ds.FieldByName('CanEncrypt').AsBoolean:=subkey.can_encrypt;
                              ds.FieldByName('CanSign').AsBoolean:=subkey.can_sign;
                              subkey := subkey.next;
                         end;
                    ds.Post;
                    err:= gpgme_op_keylist_next(context, @key);
              end;
        ds.first;
        ds.SaveToStream(result);
        if err.errorcode <> GPG_ERR_EOF then
            raise Exception.Create('cannot finish listing the keys');
     finally
        ds.Close;
        ds.Free;
        err := gpgme_op_keylist_end(context);
        FreeContext(context);
        if err.error <> 0 then
           raise Exception.Create('error when closing down key listing operation');
     end;
end;

function TGpgme.ListKeys:string;
var
   context: Tgpgme_ctx_t;
   err: Tgpgme_error;
   uid: Pgpgme_user_id;
   key: Pgpgme_key;
   subkey: Pgpgme_subkey;
   rows,columns:tstringlist;
   temp:string;
begin
     result:='';
     rows:=tstringlist.create;
     columns:=tstringlist.create;
     context:=GetContext;
     err := gpgme_op_keylist_start(context, nil, false);
     CheckGpgmeError(err);

     try
        err := gpgme_op_keylist_next(context, @key);
        while err.error = 0 do
              begin
                   uid := key.uids;
                   while assigned(uid) do
                   begin
                        if assigned(uid.uid) then
                           temp:= uid.uid else temp:='Unknown UID';
                        columns.Values['uid']:=temp;
                        if Assigned(uid.name) then
                           temp:=uid.name else temp:='';
                        columns.Values['Name']:=temp;
                        if Assigned(uid.comment) then
                           temp:=uid.comment else temp:='';
                        columns.Values['Comment']:=temp;
                        if Assigned(uid.email) then
                           temp:=uid.email else temp:='';
                        columns.Values['email']:=temp;
                        uid := uid.next;

                    end;
                   columns.Values['OwnerTrust']:=IntToSTr(key.owner_trust);
                   subkey := key.subkeys;
                   while assigned(subkey) do
                         begin
                              columns.Values['KeyID']:= subkey.keyid;
                              columns.Values['can encrypt']:=BoolToStr(subkey.can_encrypt, true);
                              columns.Values['can sign']:= BoolToStr(subkey.can_sign, true);
                              subkey := subkey.next;
                         end;
                   rows.Add(columns.CommaText);
                   columns.clear;
                   err:= gpgme_op_keylist_next(context, @key);
                   sleep(0);
              end;
         if err.errorcode <> GPG_ERR_EOF then
            raise Exception.Create('cannot finish listing the keys');

     finally
            result:= rows.Text;
            rows.free;
            columns.free;
            err := gpgme_op_keylist_end(context);
            FreeContext(context);
            if err.error <> 0 then
               raise Exception.Create('error when closing down key listing operation');
     end;
end;



function TGpgme.GetEngineInfo(): string;
var
   context: Tgpgme_ctx_t;
   info: Pgpgme_engine_info;
   alist:tstringlist;
begin
     result:='';
     context:= GetContext;
     alist:=tstringlist.create;
     try
        info := gpgme_ctx_get_engine_info(context);
        if not assigned(info) then
           raise EGpgmeError.Create('Could not get engine info');
        alist.Values['Protocol']:=gpgme_get_protocol_name(info.protocol);
        alist.Values['Version']:=info.version;
        alist.Values['File Name']:=info.file_name;
        alist.Values['HomeDir']:=info.home_dir;
        result:=alist.Text;
     finally
         FreeContext(context);
         alist.free;
     end;
end;

function gpgme_passphrase_cb(hook:pointer;uid_hint:pchar;passphrase_info:pchar;prev_was_bad:integer;fd:integer):Tgpgme_error;cdecl;
var
   password:pchar='';
   newline:pchar = #10;
begin
     password:=pchar(hook);
     gpgme_io_writen(fd,password,length(password));
     gpgme_io_writen(fd,newline,length(newline));
     result.errorcode:=GPG_ERR_NO_ERROR;
     result.error:=GPG_ERR_NO_ERROR;;
     result.errorsource:=0;
end;
procedure TGpgme.Decrypt(SrcStream, DstStream: TStream);
var
   context: Tgpgme_ctx_t;
   Src, Dst: Tgpgme_data_t;
   SrcAdapter, DstAdapter: TGpgmeStreamAdapter;
   buffer:pchar;
begin
     buffer:=nil;
     context:=GetContext;
     try
        if PassPhrase <> '' then
           begin
                fproc:=gpgme_passphrase_cb;
                buffer:=StrAlloc(length(PassPhrase)+1);
                StrPCopy(buffer,PassPhrase);
                gpgme_set_passphrase_cb(context,fproc,buffer);
           end;
        gpgme_set_armor(context,AsciiArmor);
        DstAdapter := TGpgmeStreamAdapter.Create(DstStream);
        try
           dst := DstAdapter.DH;
           SrcAdapter := TGpgmeStreamAdapter.Create(SrcStream);
           try
              Src := SrcAdapter.DH;
              CheckGpgmeError(gpgme_op_decrypt(context, Src, Dst));
           finally
                FreeAndNil(SrcAdapter);
           end;
        finally
           FreeAndNil(DstAdapter);
        end;
     finally
            if assigned(buffer) then
                StrDispose(buffer);
            FreeContext(context);
     end;
end;

procedure TGpgme.Encrypt(SrcStream, DstStream: TStream);
var
  context:Tgpgme_ctx_t;
  Src, Dst: Tgpgme_data_t;
  keys: TDynPgpgmeKeyArray;
  SrcAdapter, DstAdapter: TGpgmeStreamAdapter;
  x: Integer;
  Res: Tgpgme_error;
  key: Pgpgme_key;
begin
     if FKeys.Count = 0 then
        raise EGpgmeError.Create('No keys were selected for the encryption operation.');
    context:=GetContext;
     try
        gpgme_set_armor(context,AsciiArmor);
        SetLength(Keys, FKeys.Count + 1);
        for x := 0 to FKeys.Count - 1 do begin
          Res := gpgme_get_key(context, PChar(FKeys.Strings[x]), @key, false);
          if Res.error <> 0 then begin
            if Res.errorcode = GPG_ERR_EOF
            then raise EGpgmeError.Create('The Key with ID "' + FKeys.Strings[x] + '" was not found.')
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
           for x := 0 to Length(keys) - 1 do
               if Assigned(keys[x]) then
                  gpgme_key_release(keys[x]);
           SetLength(keys, 0);
    end;
  finally
         FreeContext(context);
  end;
end;

procedure TGpgme.Encrypt(SrcFile: AnsiString; DstStream: TStream);
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

procedure TGpgme.Encrypt(SrcStream: TStream; DstFile: AnsiString);
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

procedure TGpgme.Encrypt(SrcFile, DstFile: AnsiString);
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

constructor TGpgme.Create(libpath: string);
var
  ret:integer;
begin
      Inherited create;
     LoadGpgme(extractfilepath(paramstr(0))+libpath);
     FHomedir:=extractfilepath(paramstr(0))+'gpghome';
     FCryptopath:=extractfilepath(paramstr(0))+'gpg.exe';
     FKeys := TStringList.Create;
     FGpgmeVersion:= gpgme_check_version (nil);
end;

destructor TGpgme.Destroy;
begin
   if Assigned(FKeys) then
      FreeAndNil(FKeys);
   UnloadGpgme();
   inherited Destroy;
end;

end.

