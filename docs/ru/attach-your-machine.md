# Подключение своей машины к Dyatel

Это руководство проводит **проксера** (того, кто запускает сервер) и
**клиента** (того, кто потребляет туннель) от нуля до работающего
публичного адреса. Для обеих сторон есть два пути: **Tier-0 офлайн**
(без демона, базы и аккаунта — только рендеринг и `wg-quick`) и
**Tier-1 управляемый** (демон хранит состояние, открывает порты и
сам лечит дрейф).

Терминология (RFC §4): `проксер` — владелец хоста, экспонируемая
машина; `клиент` — потребитель, тот, кто подключается.

---

## 1. Проксер: публикация сервера за CGNAT

### 1.1 Сгенерируйте ключи локально (BYOK)

Приватный ключ не покидает вашу машину; в демон уходит только
публичная половина (RFC §3.4b).

```bash
wg genkey | tee /etc/dyatel-private.key | wg pubkey
chmod 600 /etc/dyatel-private.key
cat /etc/dyatel-private.key.pub   # публичный ключ, 44 символа
```

Для AmneziaWG используйте `awg genkey | tee ... | awg pubkey`.

### 1.2 Создайте хост

**Управляемый путь (панель).** Войдите на `https://dyatel.<domain>`,
нажмите **Add host**, вставьте публичный ключ, выберите клиента из
каталога и транспорт.

**Управляемый путь (CLI).**

```bash
export DYATEL_TOKEN=dyatel_…        # панель: Tokens -> Mint token
export DYATEL_API=https://dyatel.<domain>

dyatelctl hosts create --name tiny-mc \
  --wg-pubkey "$(cat /etc/dyatel-private.key.pub)" \
  --transport wireguard \
  --consumer-id <uuid-клиента>       # `dyatelctl users list <имя>`
```

**Tier 0 (совсем без демона).** Отрендерите обе стороны и агрегат
шлюза офлайн:

```bash
dyatelctl gen wireguard --help      # флаги: --name, --endpoint, --forwards
```

### 1.3 Получите конфиг проксера

```bash
dyatelctl hosts config proxer <host-id> --out /etc/wireguard/dyatel.conf
```

Демон отдаёт конфиг с плейсхолдером `{{PRIVATE_KEY}}` — вашего
приватного ключа у него никогда не было. Подставьте его:

```bash
sed -i "s|{{PRIVATE_KEY}}|$(cat /etc/dyatel-private.key)|" /etc/wireguard/dyatel.conf
```

### 1.4 Поднимите туннель

```bash
wg-quick up dyatel
systemctl enable wg-quick@dyatel     # по желанию: переживать перезагрузки
```

### 1.5 Откройте файрвол на стороне проксера (контракт RFC §6)

UDP-ответы шлюза уходят с его **LAN**-адреса, а не с публичного IP,
к которому вы подключались, поэтому conntrack не сопоставляет
обратный кортеж и UFW с default-deny их отбрасывает как
незапрошенные:

```bash
ufw allow in proto udp from <public-ip-шлюза> to any port <listen_port>
# если шлюз и хост в одной LAN, добавьте и LAN-путь:
ufw allow in proto udp from <lan-cidr-шлюза> to any port <listen_port>
```

### 1.6 Опубликуйте сервис

**Форварды создаёт владелец** (RFC §4): тот, кто запускает машину,
решает, что публиковать.

```bash
dyatelctl forwards create <host-id> --public-port 25565 --target-port 25565 --proto tcp --label minecraft
```

В течение одного тика reconcile шлюз откроет `25565/tcp` в UFW,
сделает DNAT на ваш туннельный IP и замаскирует обратный путь.
Проверьте:

```bash
dyatelctl status          # отчёт о дрейфе (только админ)
dyatelctl events          # ваши последние действия
```

Игроки подключаются к `<ip-шлюза>:25565`. DNS-имена для форвардов
пока не реализованы — используйте `IP:port`.

---

## 2. Клиент: потребление туннеля

1. Проксер приглашает вас клиентом хоста (панель: выбор из каталога;
   CLI: `--consumer-id`). У хоста ровно один клиент.
2. Сгенерируйте ключи локально и зарегистрируйте публичную половину:

   ```bash
   wg genkey | tee /etc/dyatel-client.key | wg pubkey
   dyatelctl hosts register-consumer-key <host-id> --wg-pubkey "$(cat /etc/dyatel-client.key.pub)"
   ```

3. Получите конфиг, подставьте ключ, поднимите туннель:

   ```bash
   dyatelctl hosts config client <host-id> --out /etc/wireguard/dyatel-client.conf
   sed -i "s|{{PRIVATE_KEY}}|$(cat /etc/dyatel-client.key)|" /etc/wireguard/dyatel-client.conf
   wg-quick up dyatel-client
   ```

4. Проверьте хендшейк и доступность туннельного IP проксера:

   ```bash
   wg show dyatel-client latest-handshakes   # ненулевая метка = туннель жив
   ping -c3 <tunnel-ip-проксера>
   ```

`AllowedIPs` в вашем конфиге — только туннельный адрес проксера,
поэтому обычный интернет-трафик идёт через ваш аплинк: туннель это
приватный путь к одной машине.

---

## 3. Диагностика

| симптом | причина | решение |
|---|---|---|
| хендшейк есть, эхо не приходит | нет маршрута или UFW проксера отбросил ответ | §1.5; проверьте `ip route get <tunnel-ip-пира>` на шлюзе |
| хендшейка нет вовсе | неверный endpoint/порт или публичный порт закрыт | `dyatelctl status`, затем `ufw status` на шлюзе |
| в конфиге `{{PRIVATE_KEY}}` | плейсхолдер не заменён | подставьте ключ из локального файла |
| `412: consumer key not registered` | клиент не отправил публичный ключ | §2 шаг 2 |
| форвард создан, но никто не слушает | reconcile ещё не прошёл | `dyatelctl reconcile` |

---

## 4. Шпаргалка

```bash
dyatelctl me                                  # кто я и каким способом авторизован
dyatelctl hosts list                          # мои хосты (владелец + клиент)
dyatelctl hosts edit <id> --keepalive 15      # только изменяемые параметры
dyatelctl tokens create --label laptop        # выпустить PAT (показывается один раз)
dyatelctl tokens list / rm <id>               # аудит / отзыв
dyatelctl users list dima                     # каталог для приглашений
dyatelctl events --limit 20                   # журнал действий
dyatelctl reconcile                           # принудительный проход цикла
```