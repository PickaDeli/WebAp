# WebAp
Back end of a messageboard webapplication.

Back End-kurssin projektin raportti

Kurssilla tehtiin sovelluksen back end-puoli, jolla voidaan pyörittää viestialustaa. Käyttäjä voi
rekisteröityä palveluun, lähettää ja vastaanottaa viestejä sekä poistaa omia viestejään.
Rakenne
Projektin rakentamiseen käytettiin ns. monikerrosrakennetta. Tämä rakenne helpottaa
projektin hallittavuutta ja on selkeämpi myös seuraavalle, jonka täytyy koodiin kajota.
Käytännössä eri toiminnallisuudet on jaoteltu omiin lokeroihin rajapintoineen.
Tämä projekti sisälsi seuraavat kerrokset, joihin jatkossa viittaan kansioina:
- Models
- Repositories
- Services
- Controllers
- Middleware
  
Kerrokset

Models
Tämä kansio sisältää tietokantataulujen mallit niin käyttäjälle kuin viestille, sekä molemmille
omat Data Transfer Objectit, joka huolehtii tiedon siirrosta eri sovelluksen osien välillä.
Tietokantaan tallennetaan käyttäjältä paljon tietoja, mutta kaikkea ei tarvitse, eikä pidä,
siirtää aina käyttäjälle näkyviin ja DTO-luokka huolehtii siitä.
Kenttien luomisen yhteydessä voidaan laittaa annotaatioita, eli tiettyjä rajoituksia, koskien
esimerkiksi kenttään mahtuvan merkkijonon kokoa. Tämä on tärkeää tietoturvankin kannalta,
koska esimerkiksi tiettyjä haittakoodeja voidaan ajaa tietokantaan käyttäjätietoja
syötettäessä ja näin ollen vaikka tallentaa tietokannasta tiedot hyökkääjän koneelle.
Tämä kansio sisältää myös MessageServiceContextin, joka hallitsee tietokantayhteyttä ja
mahdollistaa CRUD -toimintojen käytön (Create, Read, Update, Delete).

Repositories
Tämä kansio sisältää toiminnallisuudet niin käyttäjien kuin viestienkin pyörittämiseen, sekä
rajapinnat molemmille. Nämä toiminnallisuudet hoitavat liikenteen tietokannan ja palvelimen
välillä, mutta eivät suoraan näy käyttäjälle. Toiminnallisuudet ovat rakennettu asynkronisina,
jolloin ohjelma voi suorittaa useampaa tehtävää yhtä aikaa, eikä jäädy odottaessaan
vastausta tietokannasta.

Toiminnallisuudet UserRepository
- DeleteUserAsync
  o Poistaa käyttäjän, mikäli sellainen on olemassa.
- GetUserAsync
  o Hakee käyttäjän käyttäjänimen perusteella käyttäjän tiedot.
- GetUsersAsync
  o Hakee kaikkien käyttäjien tiedot.
- NewUserAsync
  o Luo uuden käyttäjän.
- UpdateUserAsync
  o Päivittää käyttäjän tietoja.
  
Toiminnallisuudet MessageRepository
- DeleteMessageAsync
  o Poistaa viestin, mikäli sellainen on olemassa.
- GetMessageAsync(id)
  o Hakee viestin id:n perusteella.
  o Sisällyttää hakuun lähettäjän (Sender) ja vastaanottajan (Recipient).
  o FirstOrDefaultAsync hakee ensimmäisen viestin, jossa on annettu id-
  arvo
- GetMessagesAsync
  o Hakee viimeisimmät 10 julkista viestiä, eli viestit, joissa vastaanottaja
  (Recipient) on null.
  o Lajittelee viestit id:n mukaan arvojärjestykseen niin, että uusimmat
  viestit (suurin id) näkyvät ensimmäisinä.
- GetMyReceivedMessagesAsync
  o Hakee 10 viimeisintä viestiä, jossa vastaanottajana on käyttäjä itse.
  o Vaihtoehtona on hakea myös käyttäjän id:n perusteella.
- NewMessageAsync
  o Lisää uuden viestin.
- UpdateMessageAsync
  o Mahdollistaa vietin muokkaamisen, mikäli sellainen löytyy.
  
Services
Tämän kansion luokat hoitavat Data Transfer Objectien toiminnan ja liikuttavat tietoa
palvelimelta käyttäjän näkyville. Nämä luokat sisältävät eri funktioiden toimintalogiikan ja
keskustelee Repositories-kansion sekä Middleware- kansion luokkien kanssa. Käytännössä
luokan varsinaisissa toiminnoissa kutsutaan aina repositorion toiminnallisuuksia, jotta tiedot
päivittyvät/poistuvat tietokannasta asti.
Esimerkiksi GetMessageAsync(long id) -funktio kutsuu IMessageRepositoryn
GetMessageAsync(id)- funktiota, joka hakee viestin tietokannasta käyttäen viestin id:tä
avaimena.

Toiminnallisuudet UserService
Luokan alussa määritellään käytettävä repositorio (rajapinta), tässä tapauksessa
IUserRepositorio sekä autentikaatiopalvelu IUserAuthenticationService.
- DeleteUserAsync
  o Tarkistaa löytyykö käyttäjää käyttäjänimen perusteella tietokannasta ja
  poistaa sen, mikäli se löytyy.
- GetUserAsync
  o Tarkistaa löytyykö käyttäjää käyttäjänimen perusteella tietokannasta ja
  palauttaa käyttäjän UserDTO:n tarjoamat tiedot.
- GetUsersAsync
  o Palauttaa listana kokoelman käyttäjien UserDTO tietoja.
- NewUserAsync
  o Tarkistaa, onko käyttäjänimi vapaa. Jos on, lisää käyttäjälle
  liittymispäivämäärän, päivämäärän, jolloin käyttäjä on ollut viimeksi
  kirjautuneena, luo käyttäjäkohtaiset evästeet
  UserAuthenticationServicessä ja palauttaa UserToDTO-olion ja
  tallentaa tiedot tietokantaan.
- UpdateUserAsync
  o Hakee tietokannasta käyttäjänimen perusteella tiedot ja päivittää ne
  uusiin.
- UserToDTO
  o Tällä luodaan User objektista uusia UserDTO-olioita ja tätä
  hyödynnetään tämän luokan toiminnoissa tallentamaan tietoa.
  
Toiminnallisuudet MessageService
Luokan alussa määritellään käytettävä reposiotorio (rajapinta), tässä tapauksessa
IMessageRepository sekä IUserRepository, jotta päästään käsiksi myös
käyttäjätietoihin.
- DeleteMessageAsync(id)
  o Hakee tietokannasta viestin id:n perusteella viestin ja poistaa sen,
  mikäli sellainen löytyy.
- GetMessagesAsync
  o Hakee viimeisimmät 10 julkista viestiä, eli viestit, joissa vastaanottaja
  (Recipient) on null.
  o Lajittelee viestit id:n mukaan arvojärjestykseen niin, että uusimmat
  viestit (suurin id) näkyvät ensimmäisinä.
- NewMessageAsync
  o Palauttaa MessageToDTO -olion, joka tallentaa uuden viestin
  tietokantaan.
- UpdateMessageAsync
  o Hakee tietokannasta viestin id:n perusteella ja päivittää viestin.
- MessageToDTO
  o Luodaan Message-objektista MessageDTO-olioita, joita hyödynnetään
  tiedon tallentamisessa tietokantaan.
  o Tässä otetaan huomioon myös mahdollisuus viestin vastaanottajaan
  (Recipient) sekä viittaus edelliseen viestiin (PrevMessageId).
- DTOToMessageAsync
  o Luo uuden viestin id:n, titlen ja bodyn MessageDTO-olioon
  o Varmistaa, että viestin lähettäjä tallentuu Sender-kenttään
  o Tarkistaa, onko viestillä vastaanottajaa (Recipient) ja tallentaa sen
  o Tarkistaa, viitataanko viestillä johonkin edelliseen viestiin ja tallentaa
  sen id:n
  
Controllers
Tässä kansiossa on kaksi controlleria, yksi viesteille ja toinen käyttäjille. Nämä controllerit
ovat osa ASP.NET Core-sovellusta ja toimivat API-ohjaimina. Controllerit käsittelevät http-
pyyntöjä ja palauttavat vastauksia.
Alussa controllerille määritellään reitti, jonka jälkeen annetaan käytettävissä olevat
rajapinnat, esim. UsersControlerilla on käytössä IUserService.
Näitä en nyt ala kauhean tarkasti avaamaan, mutta käytössä on Get, Put, Post ja Delete-
toiminnot, joita nyt tämän harjoituksen aikana Postmanin kautta käytettiin. Näillä sitten
kutsutaan noita Service-rajapinnan funktioita tekemään tehtävänsä.

Middleware
Tässä kansiossa on turvallisuuteen liittyviä toimintoja.
- ApiKeyMiddlewarella saadaan rajapinta-avaimen arvo haettua
appsettings.json-tiedostosta ja verratua sitä käyttäjän API-avaimeen. Mikäli
avainta ei löydy, palautetaan koodi 401 ”Api key missing” . Jos taas käyttäjän ja
ohjelman avainten arvot eivät täsmää, annetaan virhe 403 ”Unauthorized
Client” . Jos kaikki on ok, voidaan mennä eteenpäin.
- BasicAuthenticationHandlerilla tehdään perusautentikointia http-pyyntöjen
yhteydessä. Käytännössä tämä lukee http-pyyntöjen ”headereita” , ja vertailee
IUserAuthenticationServicen avulla käyttäjätietoja. Jos autentikointi
onnistuu, palauttaa luokka AuthenticationTicket-objektin, jota voidaan
käyttää sovelluksessa käyttäjän oikeuksien hallintaan.
- UserAuthenticationServicessä on sekä rajapinta IUserAuthenticationService
sekä toteutukset samalla sivulla. Ensin määritellään käytettävissä oleva
repositoriot ja tässä tapauksessa tarvitsemme molempia käyttöön.
- Authenticate-funktio tarkistaa ensin, onko käyttäjää tietokannassa. Jos
käyttäjä löytyy, luodaan tiivistetty salasana suolan kera, jotta voidaan
tallentaa se hashedPassword-muuttujaan. Sen jälkeen verrataan käyttäjän
salasanaa ja hashedPassword-salasanaa toisiinsa ja jos ne täsmäävät, on
käyttäjän todennus onnistunut.
- CreateUserCredentials-funktio luo käyttäjälle käyttäjäkohtaiset evästeet.
Näihin sisältyy random-numerogeneraattorin avulla luotu suola, sekä
tiivistealgoritimilla tehty tiiviste, joka tallennetaan käyttäjän salasanaan.
Näillä toimilla saadaan salasanaan lisää pituutta ja arvaamattomuutta, eikä
ns. puhdasta salasanaa ole mahdollista saada tietokannasta ulos.
- isMyMessage-funktio hakee käyttäjän käyttäjänimen perusteella
tietokannasta ja tarkistaa, löytyykö käyttäjää. Jos käyttäjä löytyy, haetaan
viesteistä viestin id:tä vastaava viesti. Seuraavaksi verrataan viestin lähettäjää
ja käyttäjää toisiinsa ja jos ne täsmäävät, palautetaan true.
Muissa tapauksissa palautetaan false.
