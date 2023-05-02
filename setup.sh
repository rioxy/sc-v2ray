#!/bin/bash
echo -e "=========================="
echo -e "Autosript vps v2ray only"
echo -e "by rioxy"
echo -e "follow my github @rioxy"
echo -e "=========================="
sleep 5
clear
mkdir /var/lib/premium-script
apt-get install -y curl unzip 
MYIP=$(curl ifconfig.me)
echo "$MYIP" >> /var/lib/premium-script/ipvps.conf
sleep 2
echo "Cek akses"
IZIN=$( curl https://raw.githubusercontent.com/rioxy/client/main/ipvps | grep $MYIP )
if [ $MYIP = $IZIN ]; then
sleep 2
echo -e "${green}Akses Diterima...${NC}"
else
sleep 2
echo -e "${red}Akses Ditolak...${NC}"
exit
fi
echo -e	"instalasi premium-script by rioxy"
sleep 2
apt install iptables iptables-persistent -y
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
timedatectl set-ntp true
systemctl enable chronyd && systemctl restart chronyd
systemctl enable chrony && systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
chronyc sourcestats -v
chronyc tracking -v
date
# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://github.com/rioxy/AutoScriptSSH/raw/main/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
# instal v2ray
echo -e "instalasi v2ray"
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
mkdir /usr/local/etc/v2ray/clients
echo -e"v2ray terinstall"
sleep 2
clear
echo -e "Persiapan instalasi"
read -p "Domain / subdomain: " domain
sleep 2
read -p "email:" email
sleep 2
echo "$domain" >> /var/lib/premium-script/domain
apt install certbot -y
certbot certonly --standalone --preferred-challenges http --agree-tos --email $email -d $domain
cp /etc/letsencrypt/live/$domain/fullchain.pem /usr/local/etc/v2ray/
cp /etc/letsencrypt/live/$domain/privkey.pem /usr/local/etc/v2ray/
cp /var/lib/premium-script/domain /usr/local/etc/v2ray/
sleep 2
clear
uuid=$(cat /proc/sys/kernel/random/uuid)
cat > /usr/local/etc/v2ray/config.json << END
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#tls
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/v2ray/fullchain.pem",
              "keyFile": "/usr/local/etc/v2ray/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/v2ray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat > /usr/local/etc/v2ray/none.json << END
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0,
            "security": "auto",
            "level": 8
#none
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/worryfree",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat > /usr/local/etc/v2ray/vless.json << END
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
#tls
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/v2ray/fullchain.pem",
              "keyFile": "/usr/local/etc/v2ray/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/v2ray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat > /usr/local/etc/v2ray/vnone.json << END
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 2082,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
#none
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/worryfree",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat > /usr/local/etc/v2ray/tr-tcp.json << END
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 2087,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${uuid}"
#tls
          }
        ],
        "fallbacks": [
          {
            "dest": 80
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/v2ray/fullchain.pem",
              "keyFile": "/usr/local/etc/v2ray/privkey.pem"
            }
          ],
          "alpn": [
            "http/1.1"
          ]
        },
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat > /usr/local/etc/v2ray/tr-ws.json << END
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "password"
          }
        ],
        "fallbacks": [
          {
            "dest": 80
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/v2ray/fullchain.pem",
              "keyFile": "/usr/local/etc/v2ray/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "/trojan-ws",
          "headers": {
            "Host": "$domain"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
END
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 2087 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 2082 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 81 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 445 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 7100 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 7200 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 7300 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 8443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2087 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2082 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 81 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 445 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 7100 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 7200 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 7300 -j ACCEPT
iptables-save > /etc/iptables/rules.v4
iptables-restore -t < /etc/iptables/rules.v4
netfilter-persistent save
netfilter-persistent reload
systemctl daemon-reload
systemctl enable v2ray.service
systemctl start v2ray.service
systemctl enable v2ray@none.service
systemctl start v2ray@none.service
systemctl enable v2ray@vless.service
systemctl start v2ray@vless.service
systemctl enable v2ray@vnone.service
systemctl start v2ray@vnone.service
systemctl enable v2ray@tr-tcp.service
systemctl start v2ray@tr-tcp.service
systemctl enable v2ray@tr-ws.service
systemctl start v2ray@tr-ws.service
systemctl restart v2ray
echo -e "Menunggu respon.."
sleep 2
apt install nginx
cat > /etc/nginx/site-available/default << END
server {
    listen 81;
    server_name $domain;
    
    #
    location /worryfree {
        proxy_pass http://127.0.0.1:80; # Port V2Ray
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Konfigurasi proxy ke VLESS
    location /vnone {
        proxy_pass https://127.0.0.1:2082; # Ganti IP dan port sesuai dengan konfigurasi VLESS
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    # konf trojan
}


server {
    listen 445 ssl;
    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 1.0.0.1;
    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    # vmess ws proxy
    location /vmess {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:443;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $http_host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
    }

     # VLESS WebSocket proxy
      location /vless {
        proxy_pass https://127.0.0.1:8443;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # WebSocket options
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_set_header Sec-WebSocket-Extensions $http_sec_websocket_extensions;
        proxy_set_header Sec-WebSocket-Protocol $http_sec_websocket_protocol;
        proxy_set_header Sec-WebSocket-Key $http_sec_websocket_key;
        proxy_set_header Sec-WebSocket-Version $http_sec_websocket_version;
      }

      # Trojan tcp Proxy
      location /trojan {
        proxy_pass http://127.0.0.1:2087;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
      }

      # trojan ws
      location /trojan-ws {
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;

        # Konfigurasi untuk meneruskan koneksi ke server V2Ray
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Konfigurasi untuk protokol Trojan over WebSocket dengan TLS
        proxy_set_header Sec-WebSocket-Key $http_sec_websocket_key;
        proxy_set_header Sec-WebSocket-Version $http_sec_websocket_version;
        proxy_set_header Sec-WebSocket-Extensions $http_sec_websocket_extensions;
        proxy_set_header Sec-WebSocket-Protocol $http_sec_websocket_protocol;

        # Konfigurasi untuk TLS
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
        proxy_ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
        proxy_ssl_trusted_certificate /path/to/trusted.crt;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 2;
    }
}
END
echo -e "waiting list.."

clear
echo -e "Selamat instalasi berhasil"
echo -e "ketik menu untuk menjalankan autoscript v2ray"
cat /root/log_instal.txt
sleep 5
rm setup.sh
exit
