<?php
class spam {

	/**
	 * Provide a completely random secret to be used to encrypt all data.
	 * This secret remains private and is not publicly viewable.
	 */
	protected static $secret = 'aH3sdf78)&*_';

	/**
	 * The amount of time a user must wait before being able to resubmit a form.
	 */
	protected static $submission_frequency = 5;
	
	/**
	 * Stores the form id as a string to be used by the JS encryption method.
	 */
	protected static $form_id;

	/**
	 * Stores the current epoch timestamp for validation.
	 */
	protected static $timestamp;

	/**
	 * Stores the user agent string for validation.
	 */
	protected static $user_agent;

	/**
	 * Stores a SHA-1 encoding of the unique validation identifiers for validation.
	 */
	protected static $randomizer;

	/**
	 * Stores all encrypted form fields and their subsequent values.
	 */
	protected static $encrypted = array();

	/**
	 * Initialize the spam prevention class form helper.
	 */
	public static function init(
		$form_method = 'POST',
		$form_action = '',
		$form_id = 'signupform'
	)
	{
		self::$form_id		= $form_id;
		self::$timestamp 	= date('U');
		self::$user_agent	= (!empty($_SERVER['HTTP_USER_AGENT'])) ? $_SERVER['HTTP_USER_AGENT'] : '';
		self::$randomizer 	= sha1(self::$secret . self::$timestamp . self::$user_agent);
		self::$randomizer	= substr(self::$randomizer, 16, 8);

		echo '<form method="' . $form_method . '" action="' . $form_action . '" id="' . $form_id . '" enctype="multipart/form-data">';
	}

	/**
	 * Validate the form submission.
	 *
	 * @access	public 	static
	 * @param	array	$input
	 */
	public static function validate(array $input)
	{
		self::$timestamp = !empty($input['ts']) ? $input['ts'] : null;
		if (self::$timestamp == null || !is_numeric(self::$timestamp)) {
			throw new Exception('The timestamp does not appear to be correct.');
		}

		// if form submitted in under 5 seconds since page load, assume cURL
		$now = time() - self::$submission_frequency;
		if (self::$timestamp > $now) {
			throw new Exception('The form was submitted within ' . self::$submission_frequency . ' seconds of page load');
		}

		// if form timestamp is over an hour ago, assume a bot submission
		$prev = $now - 3595;
		if (self::$timestamp < $prev) {
			throw new Exception('The form submission timestamp is over 1 hour old.');
		}

		// an empty randomizer value indicates a cURL type submission missing hidden inputs
		self::$randomizer = !empty($input['randomizer']) ? $input['randomizer'] : null;
		if (empty(self::$randomizer)) {
			throw new Exception('The randomizer does not appear to be correct.');
		}

		// the emailfield should remain empty and is meant to trick unsuspecting bots
		$emailfield = !empty($input['emailfield']) ? $input['emailfield'] : null;
		if (!empty($emailfield)) {
			throw new Exception('The honeypot was not empty.');
		}

		// the user agent must match the form submission user agent
		self::$user_agent = (!empty($_SERVER['HTTP_USER_AGENT'])) ? $_SERVER['HTTP_USER_AGENT'] : '';

		// make sure we have a valid submission
		$hash = sha1(self::$secret . self::$timestamp . self::$user_agent);
		$hash = substr($hash, 16, 8);
		if (self::$randomizer !== $hash) {
			throw new Exception('The randomizer encrypted value does not match.');
		}

		// load the encrypted field mapping data
		$encrypted_fields = !empty($input['encrypted']) ? $input['encrypted'] : null;
		if (empty($encrypted_fields)) {
			throw new Exception('The encrypted form field was empty.');
		}

		// decompress the array of encrypted fields
		$encrypted_fields = @unserialize(base64_decode($encrypted_fields));
		if ($encrypted_fields === false) {
			throw new Exception('The encrypted form field was not valid.');
		}

		// get the mapping of encrypted keys to actual key
		$data = array();
		foreach ($_POST as $key => $val) {
			// if the key is encrypted, add to return data array decrypted
			if (in_array($key, $encrypted_fields)) {
				$decrypted = self::encryption($key, false);
				$data[$decrypted] = self::encryption($val, false);
				unset($_POST[$key]);
			} else {
				$data[$key] = $val;
			}
		}

		// merge $_POST array with decrypted key array
		$_POST += $data;
	}

	/**
	 * Two way encryption function to encrypt/decrypt keys with
	 * the blowfish encryption algorithm.
	 *
	 * @access	public static
	 * @param	string	$text
	 * @param	bool	$encrypt	Whether to encrypt or decrypt
	 * @return	
	 */
	public static function encryption($text, $encrypt = true)
	{
		$encrypted_data = '';
		$td = mcrypt_module_open('des', '', 'ecb', '');
		$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
		if (mcrypt_generic_init($td, self::$randomizer, $iv) != -1) {
			if ($encrypt) {
				$encrypted_data = mcrypt_generic($td, $text);
				$encrypted_data = 'e' . base64_encode(utf8_encode($encrypted_data));
				$encrypted_data = str_replace(array('/', '='), array('---', '___'), $encrypted_data);
				self::$encrypted[] = $encrypted_data;
			} else {
				$text = str_replace(array('---', '___'), array('/', '='), $text);
				$text = substr($text, 1);
				$text = utf8_decode(base64_decode($text));
				$encrypted_data = trim(mdecrypt_generic($td, $text));
			}
			mcrypt_generic_deinit($td);
			mcrypt_module_close($td);
		}
		return $encrypted_data;
	}

	/**
	 * Display all necessary hidden form fields to enable
	 * successful validation and decryption.
	 */
	public static function hidden()
	{
		$output = '<input type="hidden" name="ts" value="' . self::$timestamp . '" />';
		$output .= '<input type="hidden" name="randomizer" value="' . self::$randomizer . '" />';
		$output .= '<input type="hidden" name="encrypted" value="' . base64_encode(serialize(self::$encrypted)) . '" />';
		$output .= '<input type="text" name="emailfield" value="" style="display:none;height:0;width:0;background:transparent;border:none" />';
		return $output;
	}

	/**
	 * Output the javascript necessary for converting form fields
	 * on form submission.
	 *
	 * @access	public
	 * @return	void
	 */
	public static function javascript()
	{
		if (count(self::$encrypted) > 0):
			// include the DES encryption function
			$output = '
<script type="text/javascript">
/**
 * The DES function for encrypting.
 *
 * @param	key
 * @param	message
 * @param	encrypt
 * @param	mode
 * @param	iv
 * @param	padding
 */
function des(key, message, encrypt, mode, iv, padding) {
	var spfunction1 = new Array (0x1010400,0,0x10000,0x1010404,0x1010004,0x10404,0x4,0x10000,0x400,0x1010400,0x1010404,0x400,0x1000404,0x1010004,0x1000000,0x4,0x404,0x1000400,0x1000400,0x10400,0x10400,0x1010000,0x1010000,0x1000404,0x10004,0x1000004,0x1000004,0x10004,0,0x404,0x10404,0x1000000,0x10000,0x1010404,0x4,0x1010000,0x1010400,0x1000000,0x1000000,0x400,0x1010004,0x10000,0x10400,0x1000004,0x400,0x4,0x1000404,0x10404,0x1010404,0x10004,0x1010000,0x1000404,0x1000004,0x404,0x10404,0x1010400,0x404,0x1000400,0x1000400,0,0x10004,0x10400,0,0x1010004);
	var spfunction2 = new Array (-0x7fef7fe0,-0x7fff8000,0x8000,0x108020,0x100000,0x20,-0x7fefffe0,-0x7fff7fe0,-0x7fffffe0,-0x7fef7fe0,-0x7fef8000,-0x80000000,-0x7fff8000,0x100000,0x20,-0x7fefffe0,0x108000,0x100020,-0x7fff7fe0,0,-0x80000000,0x8000,0x108020,-0x7ff00000,0x100020,-0x7fffffe0,0,0x108000,0x8020,-0x7fef8000,-0x7ff00000,0x8020,0,0x108020,-0x7fefffe0,0x100000,-0x7fff7fe0,-0x7ff00000,-0x7fef8000,0x8000,-0x7ff00000,-0x7fff8000,0x20,-0x7fef7fe0,0x108020,0x20,0x8000,-0x80000000,0x8020,-0x7fef8000,0x100000,-0x7fffffe0,0x100020,-0x7fff7fe0,-0x7fffffe0,0x100020,0x108000,0,-0x7fff8000,0x8020,-0x80000000,-0x7fefffe0,-0x7fef7fe0,0x108000);
	var spfunction3 = new Array (0x208,0x8020200,0,0x8020008,0x8000200,0,0x20208,0x8000200,0x20008,0x8000008,0x8000008,0x20000,0x8020208,0x20008,0x8020000,0x208,0x8000000,0x8,0x8020200,0x200,0x20200,0x8020000,0x8020008,0x20208,0x8000208,0x20200,0x20000,0x8000208,0x8,0x8020208,0x200,0x8000000,0x8020200,0x8000000,0x20008,0x208,0x20000,0x8020200,0x8000200,0,0x200,0x20008,0x8020208,0x8000200,0x8000008,0x200,0,0x8020008,0x8000208,0x20000,0x8000000,0x8020208,0x8,0x20208,0x20200,0x8000008,0x8020000,0x8000208,0x208,0x8020000,0x20208,0x8,0x8020008,0x20200);
	var spfunction4 = new Array (0x802001,0x2081,0x2081,0x80,0x802080,0x800081,0x800001,0x2001,0,0x802000,0x802000,0x802081,0x81,0,0x800080,0x800001,0x1,0x2000,0x800000,0x802001,0x80,0x800000,0x2001,0x2080,0x800081,0x1,0x2080,0x800080,0x2000,0x802080,0x802081,0x81,0x800080,0x800001,0x802000,0x802081,0x81,0,0,0x802000,0x2080,0x800080,0x800081,0x1,0x802001,0x2081,0x2081,0x80,0x802081,0x81,0x1,0x2000,0x800001,0x2001,0x802080,0x800081,0x2001,0x2080,0x800000,0x802001,0x80,0x800000,0x2000,0x802080);
	var spfunction5 = new Array (0x100,0x2080100,0x2080000,0x42000100,0x80000,0x100,0x40000000,0x2080000,0x40080100,0x80000,0x2000100,0x40080100,0x42000100,0x42080000,0x80100,0x40000000,0x2000000,0x40080000,0x40080000,0,0x40000100,0x42080100,0x42080100,0x2000100,0x42080000,0x40000100,0,0x42000000,0x2080100,0x2000000,0x42000000,0x80100,0x80000,0x42000100,0x100,0x2000000,0x40000000,0x2080000,0x42000100,0x40080100,0x2000100,0x40000000,0x42080000,0x2080100,0x40080100,0x100,0x2000000,0x42080000,0x42080100,0x80100,0x42000000,0x42080100,0x2080000,0,0x40080000,0x42000000,0x80100,0x2000100,0x40000100,0x80000,0,0x40080000,0x2080100,0x40000100);
	var spfunction6 = new Array (0x20000010,0x20400000,0x4000,0x20404010,0x20400000,0x10,0x20404010,0x400000,0x20004000,0x404010,0x400000,0x20000010,0x400010,0x20004000,0x20000000,0x4010,0,0x400010,0x20004010,0x4000,0x404000,0x20004010,0x10,0x20400010,0x20400010,0,0x404010,0x20404000,0x4010,0x404000,0x20404000,0x20000000,0x20004000,0x10,0x20400010,0x404000,0x20404010,0x400000,0x4010,0x20000010,0x400000,0x20004000,0x20000000,0x4010,0x20000010,0x20404010,0x404000,0x20400000,0x404010,0x20404000,0,0x20400010,0x10,0x4000,0x20400000,0x404010,0x4000,0x400010,0x20004010,0,0x20404000,0x20000000,0x400010,0x20004010);
	var spfunction7 = new Array (0x200000,0x4200002,0x4000802,0,0x800,0x4000802,0x200802,0x4200800,0x4200802,0x200000,0,0x4000002,0x2,0x4000000,0x4200002,0x802,0x4000800,0x200802,0x200002,0x4000800,0x4000002,0x4200000,0x4200800,0x200002,0x4200000,0x800,0x802,0x4200802,0x200800,0x2,0x4000000,0x200800,0x4000000,0x200800,0x200000,0x4000802,0x4000802,0x4200002,0x4200002,0x2,0x200002,0x4000000,0x4000800,0x200000,0x4200800,0x802,0x200802,0x4200800,0x802,0x4000002,0x4200802,0x4200000,0x200800,0,0x2,0x4200802,0,0x200802,0x4200000,0x800,0x4000002,0x4000800,0x800,0x200002);
	var spfunction8 = new Array (0x10001040,0x1000,0x40000,0x10041040,0x10000000,0x10001040,0x40,0x10000000,0x40040,0x10040000,0x10041040,0x41000,0x10041000,0x41040,0x1000,0x40,0x10040000,0x10000040,0x10001000,0x1040,0x41000,0x40040,0x10040040,0x10041000,0x1040,0,0,0x10040040,0x10000040,0x10001000,0x41040,0x40000,0x41040,0x40000,0x10041000,0x1000,0x40,0x10040040,0x1000,0x41040,0x10001000,0x40,0x10000040,0x10040000,0x10040040,0x10000000,0x40000,0x10001040,0,0x10041040,0x40040,0x10000040,0x10040000,0x10001000,0x10001040,0,0x10041040,0x41000,0x41000,0x1040,0x1040,0x40040,0x10000000,0x10041000);

	// create the 16 or 48 subkeys we will need
	var keys = des_createKeys (key);
	var m=0, i, j, temp, temp2, right1, right2, left, right, looping;
	var cbcleft, cbcleft2, cbcright, cbcright2
	var endloop, loopinc;
	var len = message.length;
	var chunk = 0;
	// set up the loops for single and triple des
	var iterations = keys.length == 32 ? 3 : 9; // single or triple des
	if (iterations == 3) {looping = encrypt ? new Array (0, 32, 2) : new Array (30, -2, -2);}
	else {looping = encrypt ? new Array (0, 32, 2, 62, 30, -2, 64, 96, 2) : new Array (94, 62, -2, 32, 64, 2, 30, -2, -2);}

	// pad the message depending on the padding parameter
	if (padding == 2) message += "        ";
	else if (padding == 1) {temp = 8-(len%8); message += String.fromCharCode (temp,temp,temp,temp,temp,temp,temp,temp); if (temp==8) len+=8;}
	else if (!padding) message += "\0\0\0\0\0\0\0\0";

	result = "";
	tempresult = "";

	// CBC mode
	if (mode == 1) {
		cbcleft = (iv.charCodeAt(m++) << 24) | (iv.charCodeAt(m++) << 16) | (iv.charCodeAt(m++) << 8) | iv.charCodeAt(m++);
		cbcright = (iv.charCodeAt(m++) << 24) | (iv.charCodeAt(m++) << 16) | (iv.charCodeAt(m++) << 8) | iv.charCodeAt(m++);
		m=0;
	}

	// loop through each 64 bit chunk of the message
	while (m < len) {
		left = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) | message.charCodeAt(m++);
		right = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) | message.charCodeAt(m++);

		// for Cipher Block Chaining mode, xor the message with the previous result
		if (mode == 1) {if (encrypt) {left ^= cbcleft; right ^= cbcright;} else {cbcleft2 = cbcleft; cbcright2 = cbcright; cbcleft = left; cbcright = right;}}

		// first each 64 but chunk of the message must be permuted according to IP
		temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);
		temp = ((left >>> 16) ^ right) & 0x0000ffff; right ^= temp; left ^= (temp << 16);
		temp = ((right >>> 2) ^ left) & 0x33333333; left ^= temp; right ^= (temp << 2);
		temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
		temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);

		left = ((left << 1) | (left >>> 31));
		right = ((right << 1) | (right >>> 31));

		// do this either 1 or 3 times for each chunk of the message
		for (j=0; j<iterations; j+=3) {
			endloop = looping[j+1];
			loopinc = looping[j+2];
			//now go through and perform the encryption or decryption
			for (i=looping[j]; i!=endloop; i+=loopinc) { //for efficiency
				right1 = right ^ keys[i];
				right2 = ((right >>> 4) | (right << 28)) ^ keys[i+1];
				//the result is attained by passing these bytes through the S selection functions
				temp = left;
				left = right;
				right = temp ^ (spfunction2[(right1 >>> 24) & 0x3f] | spfunction4[(right1 >>> 16) & 0x3f]
					  | spfunction6[(right1 >>>  8) & 0x3f] | spfunction8[right1 & 0x3f]
					  | spfunction1[(right2 >>> 24) & 0x3f] | spfunction3[(right2 >>> 16) & 0x3f]
					  | spfunction5[(right2 >>>  8) & 0x3f] | spfunction7[right2 & 0x3f]);
			}
			temp = left; left = right; right = temp; //unreverse left and right
		} //for either 1 or 3 iterations

		//move then each one bit to the right
		left = ((left >>> 1) | (left << 31));
		right = ((right >>> 1) | (right << 31));

		//now perform IP-1, which is IP in the opposite direction
		temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);
		temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
		temp = ((right >>> 2) ^ left) & 0x33333333; left ^= temp; right ^= (temp << 2);
		temp = ((left >>> 16) ^ right) & 0x0000ffff; right ^= temp; left ^= (temp << 16);
		temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);

		//for Cipher Block Chaining mode, xor the message with the previous result
		if (mode == 1) {if (encrypt) {cbcleft = left; cbcright = right;} else {left ^= cbcleft2; right ^= cbcright2;}}
		tempresult += String.fromCharCode ((left>>>24), ((left>>>16) & 0xff), ((left>>>8) & 0xff), (left & 0xff), (right>>>24), ((right>>>16) & 0xff), ((right>>>8) & 0xff), (right & 0xff));

		chunk += 8;
		if (chunk == 512) {result += tempresult; tempresult = ""; chunk = 0;}
	} //for every 8 characters, or 64 bits in the message

	// return the result as an array
	return result + tempresult;
}

/**
 * Creates the necessary DES keys. Takes as input a 64 bit key (56 used)
 * as an array of 2 integers and returns 16 48 bit keys.
 */
function des_createKeys (key) {
	// declaring this locally speeds things up a bit
	pc2bytes0  = new Array (0,0x4,0x20000000,0x20000004,0x10000,0x10004,0x20010000,0x20010004,0x200,0x204,0x20000200,0x20000204,0x10200,0x10204,0x20010200,0x20010204);
	pc2bytes1  = new Array (0,0x1,0x100000,0x100001,0x4000000,0x4000001,0x4100000,0x4100001,0x100,0x101,0x100100,0x100101,0x4000100,0x4000101,0x4100100,0x4100101);
	pc2bytes2  = new Array (0,0x8,0x800,0x808,0x1000000,0x1000008,0x1000800,0x1000808,0,0x8,0x800,0x808,0x1000000,0x1000008,0x1000800,0x1000808);
	pc2bytes3  = new Array (0,0x200000,0x8000000,0x8200000,0x2000,0x202000,0x8002000,0x8202000,0x20000,0x220000,0x8020000,0x8220000,0x22000,0x222000,0x8022000,0x8222000);
	pc2bytes4  = new Array (0,0x40000,0x10,0x40010,0,0x40000,0x10,0x40010,0x1000,0x41000,0x1010,0x41010,0x1000,0x41000,0x1010,0x41010);
	pc2bytes5  = new Array (0,0x400,0x20,0x420,0,0x400,0x20,0x420,0x2000000,0x2000400,0x2000020,0x2000420,0x2000000,0x2000400,0x2000020,0x2000420);
	pc2bytes6  = new Array (0,0x10000000,0x80000,0x10080000,0x2,0x10000002,0x80002,0x10080002,0,0x10000000,0x80000,0x10080000,0x2,0x10000002,0x80002,0x10080002);
	pc2bytes7  = new Array (0,0x10000,0x800,0x10800,0x20000000,0x20010000,0x20000800,0x20010800,0x20000,0x30000,0x20800,0x30800,0x20020000,0x20030000,0x20020800,0x20030800);
	pc2bytes8  = new Array (0,0x40000,0,0x40000,0x2,0x40002,0x2,0x40002,0x2000000,0x2040000,0x2000000,0x2040000,0x2000002,0x2040002,0x2000002,0x2040002);
	pc2bytes9  = new Array (0,0x10000000,0x8,0x10000008,0,0x10000000,0x8,0x10000008,0x400,0x10000400,0x408,0x10000408,0x400,0x10000400,0x408,0x10000408);
	pc2bytes10 = new Array (0,0x20,0,0x20,0x100000,0x100020,0x100000,0x100020,0x2000,0x2020,0x2000,0x2020,0x102000,0x102020,0x102000,0x102020);
	pc2bytes11 = new Array (0,0x1000000,0x200,0x1000200,0x200000,0x1200000,0x200200,0x1200200,0x4000000,0x5000000,0x4000200,0x5000200,0x4200000,0x5200000,0x4200200,0x5200200);
	pc2bytes12 = new Array (0,0x1000,0x8000000,0x8001000,0x80000,0x81000,0x8080000,0x8081000,0x10,0x1010,0x8000010,0x8001010,0x80010,0x81010,0x8080010,0x8081010);
	pc2bytes13 = new Array (0,0x4,0x100,0x104,0,0x4,0x100,0x104,0x1,0x5,0x101,0x105,0x1,0x5,0x101,0x105);

	// how many iterations (1 for des, 3 for triple des)
	var iterations = key.length > 8 ? 3 : 1; //changed by Paul 16/6/2007 to use Triple DES for 9+ byte keys
	//stores the return keys
	var keys = new Array (32 * iterations);
	// now define the left shifts which need to be done
	var shifts = new Array (0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0);
	// other variables
	var lefttemp, righttemp, m=0, n=0, temp;

	for (var j=0; j<iterations; j++) { //either 1 or 3 iterations
		left = (key.charCodeAt(m++) << 24) | (key.charCodeAt(m++) << 16) | (key.charCodeAt(m++) << 8) | key.charCodeAt(m++);
		right = (key.charCodeAt(m++) << 24) | (key.charCodeAt(m++) << 16) | (key.charCodeAt(m++) << 8) | key.charCodeAt(m++);

		temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);
		temp = ((right >>> -16) ^ left) & 0x0000ffff; left ^= temp; right ^= (temp << -16);
		temp = ((left >>> 2) ^ right) & 0x33333333; right ^= temp; left ^= (temp << 2);
		temp = ((right >>> -16) ^ left) & 0x0000ffff; left ^= temp; right ^= (temp << -16);
		temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);
		temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
		temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);

		temp = (left << 8) | ((right >>> 20) & 0x000000f0);
		left = (right << 24) | ((right << 8) & 0xff0000) | ((right >>> 8) & 0xff00) | ((right >>> 24) & 0xf0);
		right = temp;

		for (var i=0; i < shifts.length; i++) {
			if (shifts[i]) {left = (left << 2) | (left >>> 26); right = (right << 2) | (right >>> 26);}
			else {left = (left << 1) | (left >>> 27); right = (right << 1) | (right >>> 27);}
			left &= -0xf; right &= -0xf;

			lefttemp = pc2bytes0[left >>> 28] | pc2bytes1[(left >>> 24) & 0xf]
					| pc2bytes2[(left >>> 20) & 0xf] | pc2bytes3[(left >>> 16) & 0xf]
					| pc2bytes4[(left >>> 12) & 0xf] | pc2bytes5[(left >>> 8) & 0xf]
					| pc2bytes6[(left >>> 4) & 0xf];
			righttemp = pc2bytes7[right >>> 28] | pc2bytes8[(right >>> 24) & 0xf]
					  | pc2bytes9[(right >>> 20) & 0xf] | pc2bytes10[(right >>> 16) & 0xf]
					  | pc2bytes11[(right >>> 12) & 0xf] | pc2bytes12[(right >>> 8) & 0xf]
					  | pc2bytes13[(right >>> 4) & 0xf];
			temp = ((righttemp >>> 16) ^ lefttemp) & 0x0000ffff;
			keys[n++] = lefttemp ^ temp; keys[n++] = righttemp ^ (temp << 16);
		}
	}
	return keys;
}

function utf8_encode( argString ) {
    var string = (argString+"");

    var utftext = "";
    var start, end;
    var stringl = 0;

    start = end = 0;
    stringl = string.length;
    for (var n = 0; n < stringl; n++) {
        var c1 = string.charCodeAt(n);
        var enc = null;

        if (c1 < 128) {
            end++;
        } else if (c1 > 127 && c1 < 2048) {
            enc = String.fromCharCode((c1 >> 6) | 192) + String.fromCharCode((c1 & 63) | 128);
        } else {
            enc = String.fromCharCode((c1 >> 12) | 224) + String.fromCharCode(((c1 >> 6) & 63) | 128) + String.fromCharCode((c1 & 63) | 128);
        }
        if (enc !== null) {
            if (end > start) {
                utftext += string.substring(start, end);
            }
            utftext += enc;
            start = end = n+1;
        }
    }

    if (end > start) {
        utftext += string.substring(start, string.length);
    }

    return utftext;
}

function base64_encode(data) {
    var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    var o1, o2, o3, h1, h2, h3, h4, bits, i = 0, ac = 0, enc="", tmp_arr = [];

    if (!data) return data;
    data = this.utf8_encode(data+"");

    do {
        o1 = data.charCodeAt(i++);
        o2 = data.charCodeAt(i++);
        o3 = data.charCodeAt(i++);

        bits = o1<<16 | o2<<8 | o3;

        h1 = bits>>18 & 0x3f;
        h2 = bits>>12 & 0x3f;
        h3 = bits>>6 & 0x3f;
        h4 = bits & 0x3f;

        tmp_arr[ac++] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
    } while (i < data.length);

    enc = tmp_arr.join("");

    switch (data.length % 3) {
        case 1:
            enc = enc.slice(0, -2) + "==";
        break;
        case 2:
            enc = enc.slice(0, -1) + "=";
        break;
    }

    return enc;
}
</script>';

			$output .= '<script type="text/javascript">' . "\n";
			$output .= '$(function() {' . "\n";
			$output .= '$("#' . self::$form_id . '").submit(function() {' . "\n";
			$output .= '$("#' . implode(', #', self::$encrypted) . '").each(function() {' . "\n";
			$output .= 'var $this = $(this);' . "\n";
			$output .= 'var e = des("' . self::$randomizer . '", $this.val(), 1, 0);' . "\n";
			$output .= 'e = "e" + base64_encode(e);' . "\n";
			$output .= 'e = e.replace(/\//g, "---");' . "\n";
			$output .= 'e = e.replace(/=/g, "___");' . "\n";
			$output .= '$this.val(e);' . "\n";
			$output .= '});' . "\n";
			$output .= 'return true;' . "\n";
			$output .= '});' . "\n";
			$output .= '});' . "\n";
			$output .= '</script>' . "\n";
		endif;

		echo $output;
	}

}
?>
