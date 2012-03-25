ABOUT
=====
SPF30 is a PHP library which utilizes a number of recommended spambot deterrents in an attempt to reduce form submission spam. It does not utilize any form of captcha. In addition to spam prevention methods, SPF30 also handles two-way encryption of form data to prevent your form content from being easily sniffed across the wire over HTTP.

FEATURES
========
* The form submission contains a hashed value of a system defined secret key, the current date, and the user’s user agent.
* The form submission is invalidated in the event the submission timestamp exceeds a specific timeout period (default 1 hour).
* The form submission is invalidated in the event it was submitted in rapid succession (default 5 seconds).
* A hidden input honeypot is utilized in an attempt to trick bots into passing data with the field.
* A hidden hash field is validated against the submission time, user agent, and secret key.
* A hidden field is sent containing a the array of encrypted fields for decryption to their old field names.
* Decrypted form fields are written directly back to the POST array, abstracting the encryption from your backend handling.
* User specified form field names can undergo two-way DES encryption to obfuscate form field names.
* User submitted form field values can be encrypted on the frontend using a Javascript implementation of DES.
* The encryption method goes beyond simple DES encryption for the purposes of transporting UTF-8 characters in POST data.

REQUIREMENTS
============
* You must have the PHP mcrypt module installed.
* The frontend form display requires jQuery as it binds form submission to frontend encryption.

CONFIGURATION
=============
The only configurable variable you should consider changing in SPF30 out of the
box is the `$private` key used to for two way encryption. To do so, simply make
a call to the public static variable like so:

```php
<?php
spam::$private = 'my new secret key';
```

You may also tweak the `$submission_frequency`, which determines how long a user
must wait before being able to resubmit a form.

```php
// update from 5 to 10 seconds
spam::$submission_frequency = 10;
```

EXAMPLE USAGE
=============

1. Make sure you place the spf30.php file in the same directory as your sample files.
2. Create a basic HTML template, save it with a PHP extension, and include the following code:

```html
<?php require_once('./spf30.php'); ?>
<?php spam::init('POST', 'form-handler.php', 'signupform'); ?>
	<?php $name = spam::encryption('name'); ?>
	<label>Name</label>
	<input type="text" id="<?php echo $name; ?>" name="<?php echo $name; ?>" />
		
	<?php $email = spam::encryption('email'); ?>
	<label>Email Address</label>
	<input type="text" id="<?php echo $email; ?>" name="<?php echo $email; ?>" />

	<?php $phone = spam::encryption('phone'); ?>
	<label>Email Address</label>
	<input type="text" id="<?php echo $phone; ?>" name="<?php echo $phone; ?>" />

	<?php $comment = spam::encryption('comment'); ?>
	<label>Comments</span>
	<textarea name="<?php echo $comment; ?>" id="<?php echo $comment; ?>" rows="6" cols="100"></textarea>

	<!-- display hidden fields required for validation -->
	<?php echo spam::hidden(); ?>
	<button type="submit" value="submit">submit</button>
</form>
```

3. Using the same base HTML template, create a third file and include the following code:

```php
<?php
require_once('./spf30.php');
if (!empty($_POST)) {
	try {
		// this is simple an example of the form data before decryption
		var_dump($_POST);
	
		// run validation on the submitted email form
		spam::validate($this->input);
		
		// no exceptions thrown, use decrypted form data as you please
		var_dump($_POST);
	} catch (Exception $e) {
		// an error occurred with the form validation
		// ...
		echo $e->getMessage();
	}
}
?>
```