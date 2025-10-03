# Örnek KQL Saved Searches ve Basit Kurallar

Aşağıda Kibana'da Saved Search veya Detection Rule olarak kullanabileceğiniz birkaç KQL örneği bulunmaktadır.

1) Brute-force (Windows 4625) - KQL:
```
event.code: "4625" and winlog.logon.type: 3 and NOT user.name: "Guest"
```
Açıklama: Ağ üzerinden başarısız oturum açma denemelerini filtreler.

2) Şüpheli PowerShell - KQL:
```
event.code: "4688" and process.name: "powershell.exe" and (process.command_line: "-enc" or process.command_line: "-EncodedCommand" or process.command_line: "IEX")
```

3) Kaspersky kritik tehdit - KQL:
```
index:logs-kaspersky-* and threat.severity: "Critical"
```

4) Port tarama (firewall deny spike) - KQL:
```
event.dataset: "fortigate.firewall" and action: "deny" and source.ip: *
```

Not: Bu sorguları Kibana'da Saved Search veya Detection Rule olarak kaydedin ve uygun eşik/threshold ile zamanlamayı yapılandırın.
