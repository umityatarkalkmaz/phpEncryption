#My basic Encryption class
```php
$key = 'MY-SECRET-KEY';
$encryption = new Encryption($key);
```
Important as your data is encrypted with `$key`. Keep this key well for the security of your data.
```php
$encryption-> encryptUrl($data);
```
`encryptUrl()` It is for data encrypted to use in url. You can use it as a GET method or if you want to share or retrieve data from the Url.
```php
$encryption->encryptDb($data);
```
`encryptDb()` A method you can use when you want to save your data in the database as encrypted.

Example usage
```php
<?php
require 'path/to/encryption.php';
use UmitYatarkalkmaz\Encryption;
$mySecretKey = 'Very-Strong-Key';
$encryption = new Encryption($key);

$data = 'user id'
$encryptedID = $encryption-> encryptUrl($data);
echo $encryptedID;
```