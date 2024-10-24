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

Tapahtumaselostukset löytyvät Services-kansion toiminnoista.

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
  
  Poistaa käyttäjän, mikäli sellainen on olemassa.
  
- GetUserAsync
  
  Hakee käyttäjän käyttäjänimen perusteella käyttäjän tiedot.
  
- GetUsersAsync
  
  Hakee kaikkien käyttäjien tiedot.
  
- NewUserAsync
  
  Luo uuden käyttäjän.
  
- UpdateUserAsync
  
  Päivittää käyttäjän tietoja.
  
Toiminnallisuudet MessageRepository

- DeleteMessageAsync
  
  Poistaa viestin, mikäli sellainen on olemassa.
  
- GetMessageAsync(id)
  
  Hakee viestin id:n perusteella.
  Sisällyttää hakuun lähettäjän (Sender) ja vastaanottajan (Recipient).
  FirstOrDefaultAsync hakee ensimmäisen viestin, jossa on annettu id-
  arvo
  
- GetMessagesAsync
  
  Hakee viimeisimmät 10 julkista viestiä, eli viestit, joissa vastaanottaja
  (Recipient) on null.
  Lajittelee viestit id:n mukaan arvojärjestykseen niin, että uusimmat
  viestit (suurin id) näkyvät ensimmäisinä.
  
- GetMyReceivedMessagesAsync
  
  Hakee 10 viimeisintä viestiä, jossa vastaanottajana on käyttäjä itse.
  Vaihtoehtona on hakea myös käyttäjän id:n perusteella.
  
- NewMessageAsync
  
  Lisää uuden viestin.
  
- UpdateMessageAsync
  
  Mahdollistaa vietin muokkaamisen, mikäli sellainen löytyy.
  
Services
Tämän kansion luokat hoitavat Data Transfer Objectien toiminnan ja liikuttavat tietoa
palvelimelta käyttäjän näkyville. Nämä luokat sisältävät eri funktioiden toimintalogiikan ja
keskustelee Repositories-kansion sekä Middleware- kansion luokkien kanssa. Käytännössä
luokan varsinaisissa toiminnoissa kutsutaan aina repositorion toiminnallisuuksia, jotta tiedot
päivittyvät/poistuvat tietokannasta asti.

Toiminnallisuudet UserService
Luokan alussa määritellään käytettävä repositorio (rajapinta), tässä tapauksessa
IUserRepositorio sekä autentikaatiopalvelu IUserAuthenticationService.

- DeleteUserAsync
  
  Tarkistaa löytyykö käyttäjää käyttäjänimen perusteella tietokannasta ja
  poistaa sen, mikäli se löytyy.

  Tarkemmin sanottuna funktio on bool-tyyppinen totuus-arvo, joka käyttää parametrina käyttäjän käyttäjänimeä. Funktio tarkistaa IUserRepositorystä GetUserAsync-funktiolla käyttäjän          olemassaolon. Jos käyttäjä löytyy, palautetaan IUserRepositoryn DeleteUserAsync -funktio, joka poistaa käyttäjän tietokannasta. Jos käyttäjää ei löydy, palautetaan false.

- GetUserAsync
  
  Tarkistaa löytyykö käyttäjää käyttäjänimen perusteella tietokannasta ja
  palauttaa käyttäjän UserDTO:n tarjoamat tiedot.
  
  Tarkemmin sanottuna tässä funktiossa käytetään User-luokan DTO-oliota, jolloin salasana ja suola jäävät pois tiedonsiirrosta. Ensin kutsutaan IUserRepositoryn GetUserAsync-functiota        käyttäen hakuehtona (parametrina) käyttäjänimeä. Jos käyttäjänimeä ei löydy, palautetaan null. Jos käyttäjänimi löytyy, palautetaan UserToDTO-olio. UserToDTO kääntää User-olion UserDTO-    muotoon.

- GetUsersAsync
  
  Palauttaa listana kokoelman käyttäjien UserDTO tietoja.
  
  Kyseessä on siis IEnumerable Task, joka on rajapinta jolla määritellään tietojen läpikäynti. Se on erityisen hyödyllinen silloin, kun käsitellään suuria tietomääriä tai halutaan            palauttaa kokoelmia ilman, että koko kokoelmaa ladataan muistiin kerralla. Tässä kokoelma käydään läpi foreach-silmukalla, joka listaa kaikki käyttäjät IUserRepositoryn tarjoamasta         tietokannasta ja kääntää ne  UserToDTO:lla UserDTO-muotoon. Lopuksi palautetaan käyttäjät listana.

- NewUserAsync
  
  Tarkistaa, onko käyttäjänimi vapaa. Jos on, lisää käyttäjälle
  liittymispäivämäärän, päivämäärän, jolloin käyttäjä on ollut viimeksi kirjautuneena, luo käyttäjäkohtaiset evästeet
  UserAuthenticationServicessä ja palauttaa UserToDTO-olion ja tallentaa tiedot tietokantaan käyttäen IUserRepositoryn tarjoamaa NewUser-funtiota.

- UpdateUserAsync
  
  Hakee tietokannasta käyttäjänimen perusteella tiedot ja päivittää ne uusiin.
  
  Tämä on boolean-tyyppinen task, jossa ensin kutsutaan IUserRepositoryn GetUserAsync-funktiota hakemaan User-olion nykyiset tiedot. Jos tiedot löytyvät, päivitetään tiedot oliolle           tallentaen ne dbUser-muuttujaan ja palautetaan IUserRepositoryn UpdateUserAsync-funktio dbUser parametrinään. Jos käyttäjää ei löydykään, palautetaan false.

- UserToDTO
  
  Tällä luodaan User-oliosta uusia UserDTO-olioita ja tätä hyödynnetään tämän luokan toiminnoissa siirtämään tietoa.
  
Toiminnallisuudet MessageService
Luokan alussa määritellään käytettävä reposiotorio (rajapinta), tässä tapauksessa
IMessageRepository sekä IUserRepository, jotta päästään käsiksi myös
käyttäjätietoihin.

- DeleteMessageAsync(id)
  
  Hakee tietokannasta viestin id:n perusteella viestin ja poistaa sen,
  mikäli sellainen löytyy.
  
  Kyseessä on boolean-tyyppinen totuusarvo-funktio, joka hakee viestin id:llä IMessageRepositoiosta GetMessageAsync-funktiolla kyseisesn viestin. Jos viesti löytyy, poistetaan se             IMessageRepositorion DeleteMessageAsync- funktiolla. Jos viestiä ei löydy, palautetaan false.

- GetMessageAsync

  Hakee tietokannasta viestin id:n perusteella viestin.
  
  Käytännössä palauttaa MessageToDTO:n kautta MessageDTO-olion, jonka tiedot on haettu IMessageReposioryn GetMessageAsync-funktiolla viestin id:tä käyttäen.
  
  MessageRepositoryn puolella on tähän funktioon vielä lisää logiikkaa, jotta viestin lähettäjä (Sender), mahdollinen vastaanottaja (Recipient) saadaan mukaan.

- GetMessagesAsync
  
  Hakee viimeisimmät 10 julkista viestiä, eli viestit, joissa vastaanottaja (Recipient) on null ja lajittelee viestit id:n mukaan arvojärjestykseen niin, että uusimmat viestit (suurin id)    näkyvät ensimmäisinä.
  
  MessageRepositoryssä on tähänkin funktioon lisää logiikkaa, joka ottaa vastaanottajan mukaan tietoihin ja katsoo, että vastaanottaja on tosiaan null, etteivät kenenkään yksityisviestit     tulostu mukaan.
  
  MessageServicen puolella kyseessä on IEnumerable task, kun käydään isoa datamassaa läpi. Tässä seulotaan läpi IMessageRepositoryn tarjoama GetMessagesAsync-funktio ja lisätään              sopivat viestit listaan. 

- NewMessageAsync
  Tallentaa uuden viestin tietokantaan.
  
  Tässä ensin parametrina annettu MessageDTO-olio muutetaan DTOToMessageAsync-funktiolla Message-olioksi, joka sitten tallennetaan tietokantaan IMessageRepositoyn NewMessageAsync-funktiota   käyttäen. Ehkä. Monimutkainen rakenne.

- UpdateMessageAsync
  
  Hakee tietokannasta viestin id:n perusteella ja päivittää viestin.
  
  Tämä on boolean-tyyppinen totuusarvo task, jossa ensin tarkistetaan löytyykö tällä id:llä olevaa viestiä tietokannasta kutsuen IMessgeRepositoryn GetMessageAsync-funktiota. Jos viesti      löytyy, tallennetaan viestiin uusi otsikko ja body, jonka jälkeen kutsutaan IMessageRepositoryn UpdateMessageAsync-funktiota ja päivitetään viestin sisältö tietokantaan. Jos viestiä ei     löydy, palautetaan false.

- MessageToDTO
  
  Luodaan Message-objektista MessageDTO-olioita, joita hyödynnetään tiedon tallentamisessa tietokantaan.
  
  Tässä otetaan huomioon myös mahdollisuus viestin vastaanottajaan (Recipient) sekä viittaus edelliseen viestiin (PrevMessageId).

- DTOToMessageAsync
  
  Luo uuden viestin id:n, titlen ja bodyn MessageDTO-olioon
  
  Varmistaa, että viestin lähettäjä tallentuu Sender-kenttään
  
  Tarkistaa, onko viestillä vastaanottajaa (Recipient) ja tallentaa sen
  
  Tarkistaa, viitataanko viestillä johonkin edelliseen viestiin ja tallentaa sen id:n
  
Controllers

Tässä kansiossa on kaksi controlleria, yksi viesteille ja toinen käyttäjille. Nämä controllerit ovat osa ASP.NET Core-sovellusta ja toimivat API-ohjaimina. Controllerit käsittelevät http-pyyntöjä ja palauttavat vastauksia.
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
