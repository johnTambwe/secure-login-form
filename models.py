
import hashlib

users = {
    'john': {'password': hashlib.sha256('@Password123'.encode()).hexdigest(), 'failed_logins': 0},
    'jane': {'password': hashlib.sha256('!Password456'.encode()).hexdigest(), 'failed_logins': 0},
    'jonas': {'password': hashlib.sha256('&Password789'.encode()).hexdigest(), 'failed_logins': 0},
    'joanah': {'password': hashlib.sha256('^Password109'.encode()).hexdigest(), 'failed_logins': 0},
    'julia': {'password': hashlib.sha256('^Password239'.encode()).hexdigest(), 'failed_logins': 0}
}
common_passwords = [
    "hello123",
    "123654",
    "samantha",
    "panther",
    "qazxsw",
    "guitar",
    "hannah",
    "thomas",
    "killer1",
    "trust",
    "mercedes",
    "asdfghjk",
    "yamaha",
    "blahblah",
    "adminadmin",
    "welcome1!",
    "iloveyou2",
    "123456",
    "123456789",
    "qwerty",
    "password",
    "111111",
    "12345678",
    "abc123",
    "1234567",
    "password1",
    "12345",
    "1234567890",
    "123123",
    "000000",
    "Iloveyou",
    "1234",
    "1q2w3e4r5t",
    "qwertyuiop",
    "123",
    "admin",
    "qwerty123",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "login",
    "princess",
    "password123",
    "football",
    "admin123",
    "starwars",
    "sunshine",
    "master",
    "hottie",
    "loveme",
    "zaq1zaq1",
    "password1!",
    "welcome1",
    "hello",
    "freedom",
    "whatever",
    "qazwsx",
    "trustno1",
    "654321",
    "jordan23",
    "harley",
    "password!",
    "killer",
    "superman",
    "iloveyou1",
    "aaaaaa",
    "shadow",
    "biteme",
    "zaq12wsx",
    "welcome123",
    "ashley",
    "charlie",
    "jennifer",
    "snoopy",
    "michael",
    "football1",
    "password2",
    "123qwe",
    "monkey1",
    "password01",
    "asdfgh",
    "aa123456",
    "password1234",
    "welcome1234",
    "michael1",
    "123abc",
    "chocolate",
    "123456a",
    "liverpool",
    "passw0rd",
    "baseball",
    "purple",
    "jordan",
    "tigger",
    "freedom1",
    "sunshine1",
    "iloveyou!",
    "password3",
    "master1",
    "monkey123",
    "whatever1",
    "jessica",
    "jordan1",
    "london",
    "basketball"
]

