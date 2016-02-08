<?php
/***********************************************************
 *         Copyright @ Anthony E. Rutledge, 2016
 ***********************************************************
 *   Welcome to Anthony's E-mail Domain Lister!!!  Enjoy!  *
 ***********************************************************
 The Street Fighter II Championship Edition of Code Samples!
 *********************************************************** 
                     "HA-DOO-KEN!"
 ***********************************************************
 
         Date: 2/8/2016 @ 12:40 P.M.
===============================================================
    Candidate: Anthony E. Rutledge
       E-mail: anthony_rutledge_101@yahoo.com
      Website: https://www.anthonyerutledge.info
Stackoverflow: http://stackoverflow.com/users/2495645/anthony-rutledge
===============================================================
      Target: The American Society for Clinical Investigation
     Purpose: Web Developer Code Sample
===============================================================
  Web Server: Apache HTTPD 2.4.12
    Language: PHP (5.6.11); Default Character Set = UTF-8
       Style: Object Oriented
      Markup: HTML5, CSS 2.1 / 3
     Charset: UTF-8 
      Format: Single File (PHP classes, PHP client code, HTML, and CSS)
===============================================================
       Input: Strings (e-mail addresses and other) and white space (\r,\n,\t, 
              spaces, etc...).
      Source: HTML textarea, button, and hidden field (CSRF token).
      Output: An ordered and unique list of email domain names.
 Destination: HTML table, dynamically drawn.
===============================================================
      README: --GENERAL BLABBING--
 
              My programming orientation is influenced by the first languages
              I learned to program in; C, C++, Perl, and UNIX (FreeBSD) shell programming.
              
              I wonder how many people went "flashy" with lots of CSS and JavaScript.
              Hummm. I can do that, but I have no time :-).
             
              If if you are a JavaScript inclined/oriented programmer (and see the world
              through JQuery and numerous frameworks) you might want to modify
              your expectations a little bit.
 
              All code is of my own creaton (including regular expressions).
              Flashy CSS (but, not all CSS) and JavaScript have been intentionally omitted.
              I can add AJAX functionality, but that is not the goal here.

              Generally, I write code out the long way (save lines, or save sanity? Hummm).
              There may be times you say to yourself, "He does not need to do that," and "doesn't
              he know that variable and properties are NULL by default," and "why is he setting things
              to NULL then unstting them? I cannot handle that!" :-) Fear not, we all do things that,
              when faced with scrutiny, seem dumb. I am not immune to this condition!

              If you see lots of loops and such directly in someone's main HTML, run. Run, and do not stop until
              your wind born tears dry crustily on your cheeks.

              Yes, I do use extract(), but only in one specific circums. Even then, I use comments.
              You will see. Speaking of comments, I did not fill in "complete" doc blocks, but you'll understand.

              Generally speaking, the advantage of starting out with C and C++ is that you see through a lot of that fluff.
              You have to, or else you will not accomplish much. No, I am far from a perfect coder
              (ha, ha, ha, ho, ho, ho), and I am always learning things. I even make mistakes. ;-) 

              While I do not claim to have the master OOP plan for building webpages / sites,
              I can do this and more. The much ballehooed and vaunted MVC appraoch is not something
              I practice at this time. But, if I can do this, I can do that (easily).

              There are no control statements in my HTML. Method calls? Yes.

              Working code matters, but my definition of working means trust
              worthy (to the best of one's ability, given time constraints), too.

              I cannot compell myself to do this without adding basic security
              and error handling. No, I am not filtering $_SESSION. I am trying
              to get this done as quickly as possible.

              --SANITIZER & VALIDATOR CLASSES--
              http://php.net/manual/en/book.filter.php

              I use filter_input_array(), filter_input(), filter_var_array(),
              filter_var(), and filter_has_var(), but not exclusively. If you plan
              on looking for $_POST as a starting point, you may need to adjust
              your expectations. If you have never used PHP Variable Functions/Methods
              or the PHP filter stuff, *definitely* skip the sanitizer and validator classes.

              --EMAIL and REGULAR EXPRESSIONS--
 
              The HTML pattern attribute is not valid HTML (W3C) when applied to a textarea.
              It is possible, using the multiple attribute, to enter multiple email addresses
              into an <input type=email> field, but I am confident a <textarea> is what I
              need in this case.

              A valid e-mail address should have a valid local part and domain part.
              In this program, I redefine what constitutes a valid local part.

              While e-mail RFCs permit a wide range of characters (more than most
              perople realize), I have limited the scope to the following characters: [A-Za-z0-9@_.-].
              Therefore, the majority of character found at the following website will not be valid in
              email addresses for this program: https://en.wikipedia.org/wiki/Email_address

              Obviously, there are constraints on where, and how often, some of these characters
              may appear in a single e-mail address. Also, note I have redefined
              the shortest e-mail to be of the form a@b.xx, six characters in all.
              In reality, a@b is a legal, internal (to an MTA) email address.

              --THE SEVEN CODE VIRTUES--

              The words "secure" and "security" do not appear once in this article.
              http://agileinaflash.blogspot.com/2010/02/seven-code-virtues.html
              However, tested, working, and developed code might imply secure coding practices.

              Simplicity, clarity, and brevity, yes, I agree. Although,
              I appreciate secure coding practices, too. I would think the author
              could have mentioned secure coding in his "Developed" section, but no.
              Why not? It tends to spoil the "easy" and "simplicity" arguments.

              --ON THAT NOTE--

              If my input sanitization, validation, escaping, error handling, exception,
              HTML, cipher, and other classees are too much to digest right now,
              just ignore them and focus on the basics. Skip to the try/catch/finally
              statement near the bottom.
  
              Have fun picking me a part!

              --Anthony

 
===============================================================
  
 */

/**
 * Exception classes to help with error handling.
 */
class SecurityException extends RuntimeException
{   

}

class SanitizationException extends SecurityException
{
    
}

class ValidationException extends SecurityException
{

}
/***************************************************/


/**
 * A class for dealing with errors, including exceptions.
 */
class ErrorHanlder
{
    /* Properties */
    
    /*Constructor*/
    public function __construct() 
    {   
        set_exception_handler([$this, 'aerExceptionHandler']);
        set_error_handler([$this, 'aerErrorHandler'], E_ALL);   
    }

    public function aerExceptionHandler(Exception $e)
    {
        $message = date("Y-m-d H:i:s - ") . $e->getCode() .' '. $e->getMessage() .' in file '. $e->getFile() .' @ line '. $e->getLine() ."\n". $e->getTraceAsString() ."\n\n";
        //error_log($message);
        echo $message;
        exit;
    }
    
    public function aerErrorHandler($severity, $message, $file, $line, array $errorContext)
    {   
        $errorLevels = [
                             E_NOTICE            => 'Notice',
                             E_WARNING           => 'Warning',
                             E_ERROR             => 'Error',
                             E_USER_NOTICE       => 'Notice',
                             E_USER_WARNING      => 'Warning',
                             E_USER_ERROR        => 'Error',
                             E_STRICT            => 'Strict',
                             E_RECOVERABLE_ERROR => 'Recoverable Error',
                             E_DEPRECATED        => 'Deprecated',
                             E_USER_DEPRECATED   => 'Deprecated'
                        ];

        $message = date("Y-m-d H:i:s - ") . "$errorLevels[$severity]: " . "$message in file $file @ line $line\n"; 
        throw new ErrorException($message, 0, $severity, $file, $line);
    }
}


/**
 * A class for dealing with PHP sessions.
 */
class Session
{
    /* Properties */
    
    /*Constructor*/
    public function __construct() 
    {   
        $this->start();
    }

    /**
     * I could make this a static method
     */
    private function start()
    {
        if(session_status() === PHP_SESSION_NONE)
        {
            session_start();
            return;
        }
        
        if(session_status() === PHP_SESSION_ACTIVE)
        {
            session_start();
            session_regenerate_id();
        }

        return;
    }
    
    
    /**
     * I could make this a static method
     */
    public function kill()
    {   
        if(isset($_COOKIE[session_name()]))
        {
            setcookie(session_name(),'', (time() - (60*60*24*365)), '/', '', '', '');
        }
        
        session_unset();
        session_destroy();
        $_SESSION = [];
        return;
    }
}


class Utility
{
    /* Constants */
    const FBI = 'http://www.fbi.gov/about-us/investigate/cyber';

    /*Constructor*/
    public function __construct() 
    {   
        
    }


    public function debug($string)
    {
        //echo $string;
        error_log($string);
        exit;
    }
    
    public function redirect($location)
    {
        switch($location)
        {
            case 'fbi':
                $url = self::FBI;
                break;
            default:
                $url = self::FBI;
                break;
        }

        header('Content-Type: text/html; charset=utf-8');
        header("Location: $url");
    }
}

/**
 * WARNING! DANGER! "HA-DO-KEN!" NOT FOR THE FAINT OF HEART!!!
 * http://php.net/manual/en/book.filter.php
 * 
 * (Skip to Sanitizer::sanitize at the bottom for clarity.)
 * A generic, abstract super-class for filtering input.
 * 
 * Sub-classes filter by input source: INPUT_SERVER, INPUT_POST, INPUT_GET,
 * INPUT_COOKIE, $_FILES, $_SESSION, or any array that needs filtering.
 */
abstract class Sanitizer
{
    /********************** Properties *************************/
    const ENCODING = 'UTF-8';
    private $mbEncodings = ['UTF-8', 'ISO-8859-1', 'ASCII'];  //Used to establish multi-byte encoding detection order.

    //Callback scrubber
    protected $callback = 'scrubValue';     //A data scrubbing callback function.
    
    //INPUT SOURCE
    protected $superGlobalName = NULL;      //A value used in logging and error messages. Informational only.
    
    //Essential, input filtering properties.
    protected $minFilterElements = NULL;    //The smallest number of successful HTML controls allowed for a valid request.
    protected $maxFilterElements = NULL;    //The largest number of successful HTML controls allowed for a valid request.
    protected $numFilterElements = NULL;    //The number of successful HTML controls actually submitted.

    //Filtering related arrays.
    protected $maxControlCharsArray   = [];  //An array used in preliminary input checks.
    protected $userDefinedFilterArray = [];  //PHP Filter instructions for filtering, step 1. Each elements use FILTER_CALLBACK to call $this->scrub_value()
    protected $phpStringFilterArray   = [];  //PHP Filter instructions for filtering, step 2.
    protected $phpFieldFilterArray    = [];  //PHP Filter instructions for filtering, step 3.
    
    //Output related arrays.
    protected $filteredInputArray = [];      //The end result. The output.
    
    /* Abstract Methods */
    abstract protected function countInputs();          //All sub-classes must be able to count their input elements.
    abstract protected function hasRequiredElements();  //All sub-classes must be able to check if they receive all mandatory elements.
    abstract protected function hasGoodSizedElements(); //All sub-classes must be able to check if their input is right sized.
    abstract protected function sanitizeInputSource();  //All sub-classes must be able to sanitize their input source using the PHP Filter system.

    /***********************************************************/
    
    
    /* Constructor */
    public function __construct($inputName, $numElements)
    {        
        $this->setSuperGlobalName($inputName);
        $this->setNumFilterElements($numElements);
        $this->configMbString(self::ENCODING);
    }
    
    /* Destructor */
    function __destruct() 
    {
        //Destructor work.
        $this->userDefinedFilterArray = NULL;
        $this->maxControlCharArray    = NULL;
        $this->phpStringFilterArray   = NULL;
        $this->phpFieldFilterArray    = NULL;
        $this->filteredInputArray     = NULL;
        unset($this->userDefinedFilterArray, $this->maxControlCharArray, $this->phpStringFilterArray, $this->phpFieldFilterArray, $this->filteredInputArray);
    }
    

    /*Accessors*/
    public function getFilteredInputArray()
    {
        return $this->filteredInputArray;
    }
    

    /* Mutators */
    private function setSuperGlobalName($string)
    {        
        if(!is_string($string))
        {
            throw new InvalidArgumentException("The input argument, $string, must be a string.");
        }
        
        $inputSources = ['$_SERVER', '$_POST', '$_GET', '$_FILES', '$_SESSION', '$_COOKIE', '$_DATABASE'];
        
        if(!in_array($string, $inputSources, true))
        {
            throw new InvalidArgumentException("The input argument, $string, must be a valid input source.");
        }
        
        $this->superGlobalName = $string;
        
        return;
    }
    
    private function setNumFilterElements($int)
    {   
        if(!is_int($int))
        {
            throw new InvalidArgumentException('The input for setting the number of filter elements is not an integer.');
        }
        
        if(!($int > 0))
        {
            throw new DomainException("The number of filter elements must be a greater than zero(0). $int given");
        }
        
        $this->numFilterElements = $int;
        
        return;
    }
    
    public function setMinFilterElements($min, $max)
    {   
        //Validate data type.
        if(!(is_int($min) && is_int($max)))
        {
            throw new InvalidArgumentException('$min and $max must both be integers.');
        }
        
        if($min < 1)
        {
            throw new DomainException('$min must be greater than (>) zero (0).');
        }
        
        if(($min > $max))
        {
            throw new DomainException('$int must be less than or equal (<=) to the maximum number of filter elements' . "($this->maxFilterElements).");
        }

        $this->minFilterElements = $min;
        
        return;
    }
    
    public function setMaxFilterElements($max, $min)
    {   
        //Validate data type.
        if(!(is_int($max) && is_int($min)))
        {
            throw new InvalidArgumentException('$max and $min must both be integers.');
        }
        
        if($max < 1)
        {
            throw new DomainException('$max must be greater than (>) zero (0).');
        }
        
        if($max < $min)
        {
            throw new DomainException('$max must be greater than or equal to (>=) $min');
        }
        
        $this->maxFilterElements = $max;
        
        return;
    }
    
    public function setMaxControlCharsArray(array $maxCCA)
    {
        $this->maxControlCharsArray = $maxCCA;
        
        return;
    }

    public function setUserDefinedFilterArray()
    {
        foreach($this->maxControlCharsArray as $key => $value)
        {
            if(is_scalar($value))
            {
                $this->userDefinedFilterArray[$key] = ['filter'  => FILTER_CALLBACK,
                                                       'flags'   => FILTER_REQUIRE_SCALAR,
                                                       'options' => [$this, $this->callback]];
            }
            else
            {
                $this->userDefinedFilterArray[$key] = ['filter'  => FILTER_CALLBACK,
                                                       'flags'   => FILTER_REQUIRE_ARRAY,
                                                       'options' => [$this, $this->callback]];
            }
        }

        return;
    }
    
    public function setPhpStringFilterArray()
    {
        foreach($this->maxControlCharsArray as $key => $value)
        {
            if(is_scalar($value))
            {
                $this->phpStringFilterArray[$key] = ['filter' => FILTER_SANITIZE_STRING,
                                                     'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_HIGH]; //FILTER_FLAG_STRIP_LOW | 
            }
            else
            {
                $this->phpStringFilterArray[$key] = ['filter' => FILTER_SANITIZE_STRING,
                                                     'flags'  => FILTER_REQUIRE_ARRAY | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_HIGH]; //FILTER_FLAG_STRIP_LOW |
            }
        }
        
        return;
    }
    
    public function setPhpFieldFilterArray(array $phpFFA)
    {
        $this->phpFieldFilterArray = $phpFFA;
        
        return;
    }
    
    
    /* Helper Methods */
    private function configMbString($encoding)
    {        
        mb_internal_encoding($encoding);
        mb_regex_encoding($encoding);
        mb_substitute_character(0xfffd); //REPLACEMENT CHARACTER
        mb_detect_order($this->mbEncodings);
    }
    

    /* User defined filtering methods */
    private function isUTF8($encoding, $value)
    {
        if(($encoding === 'UTF-8') && (utf8_encode(utf8_decode($value)) === $value))
        {
            return true;
        }
        
        return false;
    }
    
    private function utf8tify(&$value)
    {
        $stringEncoding = mb_detect_encoding($value, $this->mbEncodings, true);
        
        if(!$stringEncoding) //Did the encoding detection pass?
        {
            $value = NULL;
            throw new RuntimeException("Sanitizer was unable to detect character encoding of input value.");
        }
        
        if($this->isUTF8($stringEncoding, $value)) //Is the value really encoded as UTF-8?
        {
            return;
        }
        else //No
        {
            $value = mb_convert_encoding($value, 'UTF-8', $stringEncoding);          //Try converting it.
            $stringEncoding = mb_detect_encoding($value, $this->mbEncodings, true);  //Now detect the encoding.

            if($this->isUTF8($stringEncoding, $value)) //Is the value UTF-8 now??
            {
                return;
            }
            else //No, dump it. Halt.
            {
                $stringEncoding = NULL;
                $value          = NULL;
                unset($stringEncoding, $value);
                throw new RuntimeException("Sanitizer was unable to the convert character encoding of a value to UTF-8.");
            }
        }
    }

    private function convertToUTF8(&$value)     //Get UTF-8 before filtering.
    {
        if(is_scalar($value))
        {
            do
            {
                $old = $value;
                $this->utf8tify($value); //Converts to UTF-8, if necessary.

                if($value === $old)
                {
                    break;
                }
            } while(1);
        }
        elseif(is_array($value) && !empty($value))
        {
            foreach($value as $field => &$string)
            {
                do
                {
                    $old = $string;
                    $this->utf8tify($string); //Converts to UTF-8, if necessary.

                    if($string === $old)
                    {
                        break;
                    }
                } while(1);
            }
        }
        else
        {
           throw new InvalidArgumentException("The argument to this function is not scalar and not an array.");
        }
        
        return;
    }

    private function trimValues(&$value)
    {    
        if(is_scalar($value))
        {
            do
            {
                $old = $value;
                $value = trim($value);

                if($value === $old)
                {
                    break;
                }
            } while(1);
        }
        else if(is_array($value) && !empty($value))
        {
            foreach($value as $field => &$string)
            {
                do
                {
                    $old = $string;
                    $string = trim($string);

                    if($string === $old)
                    {
                        break;
                    }
                } while(1);
            }
        }
        else
        {
           throw new InvalidArgumentException("The argument to this function is not scalar and not an array.");
        }
        
        return;
    }

    private function replaceStrings(&$subject)
    {
        $search  = ['U+0025', '%25', '\x25'];
        $replace = ['', '', ''];

        if(is_scalar($subject))
        {
            do
            {
                $old = $subject;
                $subject = str_ireplace($search, $replace, $subject);

                if($subject === $old)
                {
                    break;
                }
            } while(1);
        }
        else if(is_array($subject) && !empty($subject))
        {
            foreach($subject as $field => &$string)
            {
                do
                {
                    $old = $string;
                    $string = str_ireplace($search, $replace, $string);

                    if($string === $old)
                    {
                        break;
                    }
                } while(1);
            }
        }
        else
        {
           throw new InvalidArgumentException("The argument to this function is not scalar and not an array.");
        }
        
        return;
    }

    private function removeHtml(&$value)
    {    
        if(is_scalar($value))
        {
            do
            {
                $old = $value;
                $value = strip_tags($value);

                if($value === $old)
                {
                    break;
                }
            } while(1);
        }
        else if(is_array($value) && !empty($value))
        {
            foreach($value as $field => &$string)
            {
                do
                {
                    $old = $string;
                    $string = strip_tags($string);

                    if($string === $old)
                    {
                        break;
                    }
                } while(1);
            }
        }
        else
        {
           throw new InvalidArgumentException("The argument to this function is not scalar and not an array.");
        }
        
        return;
    }

    private function removeBackslashes(&$value)
    {    
        if(is_scalar($value))
        {
            do
            {
                $old = $value;
                $value = stripslashes($value);

                if($value === $old)
                {
                    break;
                }
            } while(1);
        }
        else if(is_array($value) && !empty($value))
        {
            foreach($value as $field => &$string)
            {
                do
                {
                    $old = $string;
                    $string = stripslashes($string);

                    if($string === $old)
                    {
                        break;
                    }
                } while(1);
            }
        }
        else
        {
           throw new InvalidArgumentException("The argument to this function is not scalar and not an array.");
        }
        
        return;
    }
    

    /*Callback Method)*/
    protected function scrubValue($value)       //Applied to each successful HTML control via FILTER_CALLBACK
    {
        $this->convertToUTF8($value);
        $this->trimValues($value);
        $this->replaceStrings($value);
        $this->trimValues($value);
        $this->removeBackslashes($value);
        $this->trimValues($value);
        $this->removeHtml($value);
        $this->trimValues($value);

        do
        {
            $oldValue = $value;

            $this->convertToUTF8($value);
            $this->trimValues($value);
            $this->replaceStrings($value);
            $this->trimValues($value);
            $this->removeBackslashes($value);
            $this->trimValues($value);
            $this->removeHtml($value);
            $this->trimValues($value);

            if($value === $oldValue)
            {
                break;
            }
        } while(1);

        return $value;
    }

    
    /*Preliminary input data checks.*/    
    protected function isGoodCallback()
    {
        //Validate input type.
        if(!is_string($this->callback))
        {
            throw new InvalidArgumentException('$this->callback must be a string.');
        }
        
        //Validate that this instance has a callback method.
        if(!method_exists($this, $this->callback))
        {
            throw new BadMethodCallException("Method $this->callback does not exist in this object instance.");
        }
        
        
        $methodVar = [$this, $this->callback]; //http://php.net/manual/en/function.is-callable.php
        
        //Validate callability.
        if(!is_callable($methodVar))
        {
            throw new BadMethodCallException("Method $this->callback is not callable.");
        }

        return true;
    }
    
    protected function hasMinNumElements()
    {
        if(($this->numFilterElements < $this->minFilterElements))
        {
            throw new RangeException("$this->superGlobalName requires at least $this->minFilterElements elements. Not enough ($this->numFilterElements) submitted.", 301);
        }
        
        return true;
    }
    
    protected function hasNotExceededMaxNumElements()
    {
        if($this->numFilterElements > $this->maxFilterElements)
        {
            throw new RangeException("$this->superGlobalName cannot exceed $this->maxFilterElements elements. Too many ($this->numFilterElements) submitted.");
        }

        return true;
    }

    protected function isValidFilterArrayResult($phase)
    {
        $errorKeys = [];
        
        if(!empty($this->filteredInputArray))
        {
            foreach($this->filteredInputArray as $key => $value)
            {
                if(is_scalar($value))
                {
                    if(($value === false) || ($value === NULL))
                    {
                        $errorKeys[$key] = $key;
                    }
                }
                elseif(is_array($value))
                {
                    foreach($value as $subKey => $subValue)
                    {
                        if(($subValue === false) || ($subValue === NULL))
                        {
                            $errorKeys[$key][$subKey] = $subKey;
                        }
                    }
                }
                else
                {
                    throw new InvalidArgumentException('The PHP filter has returned an unknown data type.' . print_r($this->filteredInputArray,true));
                }
            }
        }

        //Process $errorKeys array and make a string, if necessary.
        if(!empty($errorKeys))
        {
            $errors = '';
            
            foreach($errorKeys as $key => $value)
            {
                if(is_scalar($value))
                {
                    $errors .= $value . ' ' ;
                }
                else
                {
                    foreach($value as $subKey => $subValue)
                    {
                        $errors .= $subValue . ' ';
                    }
                }
            }
            
            throw new SanitizationException("$phase. Filter failed on: " .$errors. ' form field(s).');
        }
        
        return;
    }

    
    /*The unifying reason for it all.
     * http://php.net/manual/en/filter.filters.sanitize.php
     * 
     * Errors throw exceptions. 
     * Sanitization works, or it does not.
     * 
     * Sanitization is a four step process.
     * 1) Preliminary checks (isGoodCallback(), hasMinNumElements(), hasNotExceededMaxNumElements(), hasRequiredElements(), hasGoodSizedElements())
     * 2) PHP FILTER: FILTER_CALLBACK  (User defined, iterative filter: $this->callback, a.k.a scrub_value()).
     * 3) PHP FILTER: FILTER_SANITIZE_STRING
     * 4) PHP FILTER: FILTER_SANITIZE_*, where * is EMAIL, URL, INT, STRING, or other.
     */
    public function sanitize()
    {
        if($this->isGoodCallback()                    &&
                $this->hasMinNumElements()            &&
                $this->hasNotExceededMaxNumElements() &&
                $this->hasRequiredElements()          &&  //Defined in sub-classes
                $this->hasGoodSizedElements())            //Defined in sub-classes
        {
            $this->sanitizeInputSource(); //Ensures UTF-8 encoding and performs a three step sanitization process.
        }
        return;
    }
}

/*
 * WARNING! DANGER! NOT FOR THE FAINT OF HEART!!!
 * http://php.net/manual/en/book.filter.php
 * 
 * This is used to santize HTTP requests.
 */
class ServerSanitizer extends Sanitizer
{
    /* Properties */
    const INPUT_SOURCE = '$_SERVER';

    //For filtering the HTTP_REFERER during an HTTP POST request.
    /**********************************/
    private $extInputElement     = NULL;
    private $filteredExtElement  = NULL;
    private $maxHttpRefererChars = 256;
    /**********************************/

    /* Constructor */
    public function __construct() 
    {
        parent::__construct(self::INPUT_SOURCE, $this->countInputs());
    }

  
    /*Accessors*/
    public function getFilteredExtElement()       //When filtering just one element. Typically, the HTTP_REFERER when sanitizing a POST request.
    {
        return $this->filteredExtElement;
    }
    
    
    /*Mutators*/
    public function setExtInputElement($element)  //When filtering just one element. Typically, the HTTP_REFERER when sanitizing a POST request.
    {
        if(!is_scalar($element))
        {
            throw new InvalidArgumentException('$value must be scalar.');
        }
        
        if(!is_string($element))
        {
            throw new InvalidArgumentException('$value must be string.');
        }
        
        $this->extInputElement = $element;
        
        return;
    }


    /* Helper Methods */
    protected function countInputs()
    {
        if(isset($_SERVER) && is_array($_SERVER) && !empty($_SERVER))
        {
            return count(filter_input_array(INPUT_SERVER));
        }
        else
        {
            throw new Exception('The server superglobal is missing! Cannot count $_SERVER inputs.');
        }
    }
    
    protected function hasRequiredElements()
    {
        foreach($this->maxControlCharsArray as $key => $value)
        {
            if(!filter_has_var(INPUT_SERVER, $key))
            {
                throw new OutOfBoundsException("The index $key does not exist in {$this->superGlobalName}!");
            }
        }

        return true;
    }
    
    private function hasGoodStringLengths()
    {
        foreach($this->maxControlCharsArray as $key => $value)
        {   
            if(is_scalar($value))
            {
                if(mb_strlen($_SERVER[$key]) > $value)
                {   
                    throw new RangeException("The input for *** $key *** is too large!");
                }
            }
            elseif(is_array($value))
            {
                foreach($value as $subKey => $subValue)
                {
                    if(mb_strlen($_SERVER[$key][$subKey]) > $subValue)
                    {   
                        throw new RangeException("The input for *** $subKey *** is too large!");
                    }
                }
            }
            else
            {
                return false;
            }
        }
        
        return true;
    }
    
    protected function hasGoodSizedElements()
    {
        if($this->hasGoodStringLengths())
        {
            return true;
        }
        
        return false;
    }
    
    protected function sanitizeInputSource()
    {
        $error1 = 'User defined filter error at phase (';
        $error2 = 'PHP string filter error at phase (';
        $error3 = 'PHP field filter error at phase (';
        
        $int = 1;

        $filterPhase = $error1 .$int. ')';
        $this->filteredInputArray = filter_input_array(INPUT_SERVER, $this->userDefinedFilterArray);             //USER Defined filtering for $_SERVER.
        $this->isValidFilterArrayResult($filterPhase);

        $filterPhase = $error2 .++$int. ')';
        $this->filteredInputArray = filter_var_array($this->filteredInputArray, $this->phpStringFilterArray);    //PHP string filtering for $_SERVER..
        $this->isValidFilterArrayResult($filterPhase);

        $filterPhase = $error3 .++$int. ')';
        $this->filteredInputArray = filter_var_array($this->filteredInputArray, $this->phpFieldFilterArray);     //PHP field specific filtering for $_SERVER.
        $this->isValidFilterArrayResult($filterPhase);
        
        return;
    }
    
    private function isValidFilterElementResult($phase)
    {
        if($this->filteredExtElement === false || $this->filteredExtElement === NULL)
        {
            throw new SanitizationException("Phase $phase scalar filter failed on: " . $this->extInputScalar);
        }
        
        return;
    }
    
    
    /*Public Methods*/
    public function httpRefererExists()
    {
        if(filter_has_var(INPUT_SERVER, 'HTTP_REFERER'))
        {
            return;
        }
        
        throw new SecurityException("The HTTT POST request is coming from an undefined source. No HTTP REFERER present in HTTP headers.");
    }
    
    public function httpRefererHasGoodSize()
    {
        if(!(mb_strlen($_SERVER['HTTP_REFERER']) > $this->maxHttpRefererChars))
        {
            return;
        }
        
        throw new SecurityException("The HTTP REFERER is too long. More than MAX number of characters submitted.");
    }
    
    public function sanitizeElement()
    {
        
        $options = [
                    'options' => [$this, $this->callback],
                    'flags'   => FILTER_REQUIRE_SCALAR
                   ];
        
        $int = 1;
        $filterPhase = 'userDefined(' .$int. ')';
        $this->filteredExtElement = filter_input(INPUT_SERVER, $this->extInputElement, FILTER_CALLBACK, $options);  //Filter just one element (usually, HTTP_REFERER on a POST request) of INPUT_SERVER.
        $this->isValidFilterElementResult($filterPhase);
        
        $filterPhase = 'phpString(' .++$int. ')';
        $this->filteredExtElement = filter_var($this->filteredExtElement, FILTER_SANITIZE_STRING, FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
        $this->isValidFilterElementResult($filterPhase);
        
        $filterPhase = 'phpField(' .++$int. ')';
        $this->filteredExtElement = filter_var($this->filteredExtElement, FILTER_SANITIZE_URL, FILTER_REQUIRE_SCALAR);
        $this->isValidFilterElementResult($filterPhase);
        
        return;
    }
}


/**
 * WARNING! DANGER! NOT FOR THE FAINT OF HEART!!!
 * http://php.net/manual/en/book.filter.php
 * 
 * A sub-class that contains filtering methods specific
 * to filtering HTTP POST requests. It uses custom filters
 * and PHP Filters together. In order to do this, it must
 * ensure proper input encoding (UTF-8). 
 * 
 * This class must receive filtering instructions to keep it
 * generic and useable on any page. Those instructions are
 * kept in a Webage sub-class (and would be for any web page,
 * each webpage having its own "Webpage" sub-class.
 * 
 * Technically, INPUT_POST and $_POST are not the same thing.
 */
class PostSanitizer extends Sanitizer
{
    /* Properties */
    const INPUT_SOURCE = '$_POST';  //Informational. It does not mean $_POST, literally.

    /* Constructor */
    public function __construct()
    {        
        parent::__construct(self::INPUT_SOURCE, $this->countInputs());
    }
    
    
    /* Helper Methods */
    protected function countInputs()
    {
        $count = 0;
        
        if(isset($_POST) && is_array($_POST) && !empty($_POST))
        {
            foreach(filter_input_array(INPUT_POST) as $value)
            {
                if(is_scalar($value))
                {
                    ++$count;
                }
                elseif(is_array($value))
                {
                    foreach($value as $subvalue)
                    {
                        ++$count;
                    }
                }
                else
                {
                    throw new Exception('The input data structure is irregular. Cannot count HTTP POST inputs.');
                }
            }
        }
        else
        {
            throw new SecurityException('The $_POST superglobal is malformed or empty.');
        }
        
        return $count;
    }
    
    protected function hasRequiredElements()
    {   
        foreach($this->maxControlCharsArray as $key => $value)
        {
            if(!filter_has_var(INPUT_POST, $key))
            {
                throw new OutOfBoundsException("The index $key does not exist in {$this->superGlobalName}!");
            }
        }

        return true;
    }
    
    private function hasGoodStringLengths()
    {
        foreach($this->maxControlCharsArray as $key => $value)
        {   
            if(is_scalar($value))
            {
                if(mb_strlen($_POST[$key]) > $value)
                {   
                    throw new RangeException("The input for *** $key *** is too large!");
                }
            }
            elseif(is_array($value))
            {
                foreach($value as $subKey => $subValue)
                {
                    if(mb_strlen($_POST[$key][$subKey]) > $subValue)
                    {   
                        throw new RangeException("The input for *** $subKey *** is too large!");
                    }
                }
            }
            else
            {
                return false;
            }
        }
        
        return true;
    }
    
    protected function hasGoodSizedElements()
    {
        if($this->hasGoodStringLengths())
        {
            return true;
        }
        
        return false;
    }
    
    protected function sanitizeInputSource()
    {
        //Informational. Simply used to help construct error messages.
        $error1 = 'User defined filter error at phase (';
        $error2 = 'PHP string filter error at phase (';
        $error3 = 'PHP field filter error at phase (';
        
        $int = 1;
        
        $filterPhase = $error1 .$int. ')';
        $this->filteredInputArray = filter_input_array(INPUT_POST, $this->userDefinedFilterArray);           //USER Defined filtering for INPUT_POST
        $this->isValidFilterArrayResult($filterPhase);
        
        $filterPhase = $error2 .++$int. ')';
        $this->filteredInputArray = filter_var_array($this->filteredInputArray, $this->phpStringFilterArray); //PHP string filtering for INPUT_POST.
        $this->isValidFilterArrayResult($filterPhase);

        $filterPhase = $error3 .++$int. ')';
        $this->filteredInputArray = filter_var_array($this->filteredInputArray, $this->phpFieldFilterArray); //PHP field specific filtering for INPUT_POST.
        $this->isValidFilterArrayResult($filterPhase);
        
        return;
    }
}


/**
 * A class that manages cleaning input data.
 */
abstract class Cleaner
{
    /* Properties */

    //Objects
    private $sanitizer = NULL;
    
    /* Constructor */
    public function __construct(Sanitizer $sanitizer, $minFilterElements, $maxFilterElements, array $maxCCA, array $phpFFA, array $transitoryInputs = NULL)
    {
        $this->sanitizer = $sanitizer;
        $this->programSanitizer($minFilterElements, $maxFilterElements, $maxCCA, $phpFFA, $transitoryInputs);
    }
    
    /* Validators */
    private function isValidInt($int)
    {
        if(!(is_int($int) && ($int > 0)))
        {
            throw new InvalidArgumentException("{$int} is NOT an integer greater than -1");
        }
        
        return;
    }
    
    /* This method makes it easier to work with unsuccessful checkbox controls.
     * Why? Unsuccessful checkbox controls do not register in POST or GET. */
    protected function pruneSanitizer(array &$maxCCA, array &$phpFFA, array $transitoryInputs)
    {
        foreach($transitoryInputs as $value)
        {
            if(!filter_has_var(INPUT_POST, $value))      //If the transitory HTML control is not successful.
            {
                unset($maxCCA[$value], $phpFFA[$value]); //Remove the filter instructions for it.
            }
        }
        
        return;
    }
    
    protected function programSanitizer($minFilterElements, $maxFilterElements, array $maxCCA, array $phpFFA, array $transitoryInputs = NULL)
    {
        $this->isValidInt($minFilterElements);
        $this->isValidInt($maxFilterElements);
        
        if(isset($transitoryInputs))
        {
            $this->pruneSanitizerInstructions($maxCCA, $phpFFA, $transitoryInputs);
        }
        
        $this->sanitizer->setMinFilterElements($minFilterElements, $maxFilterElements);
        $this->sanitizer->setMaxFilterElements($maxFilterElements, $minFilterElements);
        $this->sanitizer->setMaxControlCharsArray($maxCCA);
        $this->sanitizer->setUserDefinedFilterArray();
        $this->sanitizer->setPhpStringFilterArray();
        $this->sanitizer->setPhpFieldFilterArray($phpFFA);
        return;
    }
    
    public function getCleanData()
    {
        return $this->sanitizer->getFilteredInputArray();
    }
    
    public function clean()
    {
        $this->sanitizer->sanitize();
    }
}


/**
 * A class that manages cleaning of HTTP REQUEST (INPUT_SERVER)
 * data for the Domain Page.
 */
class ServerCleaner extends Cleaner
{
    /* Properties */    



    /* Constructor */
    public function __construct(ServerSanitizer $sanitizer)
    {
        
        $minFilterElements = 30;  //Lowered just for this example. SSL/TLS webservers tend to have a higher minimum.
        $maxFilterElements = 100; //Raised just for this example. SSL/TLS webservers tend to have a higher maxiumu.

        $maxCCA = [
                    'HTTP_HOST'       => 50,
                    'HTTP_USER_AGENT' => 512,
                    'REMOTE_ADDR'     => 15,
                    'REQUEST_METHOD'  => 4,
                    'REQUEST_URI'     => 256
                  ];

        $phpFFA = [
                    'HTTP_HOST'       => ['filter' => FILTER_SANITIZE_URL,
                                          'flags'  => FILTER_REQUIRE_SCALAR],
                    'HTTP_USER_AGENT' => ['filter' => FILTER_SANITIZE_STRING,
                                          'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH],
                    'REMOTE_ADDR'     => ['filter' => FILTER_SANITIZE_STRING,
                                          'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH],
                    'REQUEST_METHOD'  => ['filter' => FILTER_SANITIZE_STRING,
                                          'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH], 
                    'REQUEST_URI'     => ['filter' => FILTER_SANITIZE_STRING,
                                          'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH]
                  ];

        $transitoryInputs = NULL; //Where "transitory" means inputs may, or may not, succeed upon form submission.
        
        parent::__construct($sanitizer, $minFilterElements, $maxFilterElements, $maxCCA, $phpFFA, $transitoryInputs);
    }
}


/**
 * A class that manages cleaning of HTTP POST data for the Domain Page.
 */
class DomainPageCleanerPOST extends Cleaner
{
    /* Properties */ 

    /* Constructor */
    public function __construct(PostSanitizer $sanitizer)
    {
        $minFilterElements = 3;
        $maxFilterElements = 3;

        $maxCCA = [
                        'compositeStr' => PHP_INT_MAX, //Yes, I know, it's a limit.
                        'listBtn'      =>  4,
                        'token'        => 32
                      ];

        $phpFFA = [
                        'compositeStr' => ['filter' => FILTER_SANITIZE_STRING,
                                           'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_HIGH],
                        'listBtn'      => ['filter' => FILTER_SANITIZE_STRING,
                                           'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH],
                        'token'        => ['filter' => FILTER_SANITIZE_STRING,
                                           'flags'  => FILTER_REQUIRE_SCALAR | FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH]
                      ];

        $transitoryInputs = NULL; //Where "transitory" means inputs may, or may not, succeed upon form submission.
        
        parent::__construct($sanitizer, $minFilterElements, $maxFilterElements, $maxCCA, $phpFFA, $transitoryInputs);
    }
}

/**
 * WARNING: NOT FOR THE FAINT OF HEART!!!
 * http://php.net/manual/en/filter.filters.validate.php
 * 
 * An abstract super-class that contains core input validation methods,
 * independent of the target webpage and its associated request method.
 * It has properties to keep track of filtered input, validation errors,
 * error messages, translated input data, and more.
 * 
 * This class recieves validation instructions from sub-classes.
 */
abstract class Validator
{
    /*Properties*/
    
    //Input in need of validation.
    protected $filteredInputArray      = []; //Always populated upon instantiation.
    
    //Used during processing/validation
    protected $phpFieldValidationArray = []; //Holds PHP Filter Validate instructions.
    protected $phpFieldErrMsgsArray    = []; //Holds the error messages for PHP Filter Validate failures.
    protected $validationMetaArray     = []; //Holds custom values used to validate input.

    //Output related
    protected $testResultsArray        = []; //Holds the results of validation tests.
    protected $errorMessagesArray      = []; //Holds the final error messages for each input, if any.
    protected $translatedInputArray    = []; //In this case, the output needs escaping to help deter Cross Site Scripting attacks.
    
    /*Abstract Methods*/
    abstract protected function isVoidInput(); //Checks for input that is not truly valid. Example: blank form submissions.
    abstract protected function myValidator(); //The mail line of all Validation sub-classes. Look for it!!!!
    
    
    /*Constructor*/
    public function __construct(array $phpFVA, array $phpFEMA, array $validationMA, array $filteredInput) 
    {
        $this->phpFieldValidationArray = $phpFVA;
        $this->phpFieldErrMsgsArray    = $phpFEMA;
        $this->validationMetaArray     = $validationMA;
        $this->filteredInputArray      = $filteredInput;
    }
    
    //Getters for necessary OUTPUT
    
    /**
     * Used to return filtered data when validation fails.
     * Frequently helps populate sticky forms.
     */
    public function getFilteredInputArray()  //Used in a main line when validate()returns false. Provides data for sticky forms.
    {
        return $this->filteredInputArray;
    }

    
    /**
     * Gets all the error messages that have been accumulated from:
     * 1. PHP Filter Validate Tests.
     * 2. Variable functions called by Validate::coreValidationLogic().
     * 3. Spcial case tests specific to a sub-class.
     */
    public function getErrorMessagesArray()  //Allows the user to find out what went wrong.
    {
        //You need the escaper.
        return $this->errorMessagesArray;
    }
    
    
    /**
     * Only used when validation fails.
     * Returns CSS classes, or codes (for  AJAX).
     */
    public function getClasses($ajax = false)  //Translates test results into CSS classes.
    {
        foreach($this->testResultsArray as $key => $value)
        {
            if(($value === true) && ($ajax === false)) //If the test passed.
            {
                $this->testResultsArray[$key] = 'goodNodes';  //See the CSS file for specifics.
            }
            elseif(($value === true) && ($ajax === true))
            {
                $this->testResultsArray[$key] = '1';
            }
            elseif(($value === false) && ($ajax === false))
            {
                $this->testResultsArray[$key] = 'badNodes';
            }
            else
            {
                $this->testResultsArray[$key] = '0';
            }
        }

        return $this->testResultsArray;
    }
  
    
    /**
     * Used when validation is successful.
     * 
     * Translated input is GOOD, and possibly conditioned, data ready for outputting.
     * Ninety-nin percent (99%) of the time, this method will NOT be called inside
     * of a child::myValidator() method unless ALL validation tests pass.
     */
    public function getTranslatedInputArray()
    {
        return $this->translatedInputArray;
    }
    
    
    /*
     * Method that compares two values
     * to see if they are equal, but not identical.
     */
    protected function equal($y1, $y2)
    {
        return ($y1 == $y2) ? true : false; //I don't use ternary statements often, but this is ok.
    }
    
    /*
     * Method that compares two values
     * to see if they are identical.
     */
    protected function identical($y1, $y2)
    {
        return ($y1 === $y2) ? true : false; //I don't use ternary statements often, but this is ok.
    }
    
    /**
     * Converts PHP Filter errors (false/NULL) to textual error messages.
     * These error messages are stored in Validator::phpFieldErrMsgsArray.
     * 
     * Inside of any sub-classes myValidator() method, since PHP Filter tests occur before my
     * own personal validation tests, my tests (be feild) do not execute if an
     * error already exists (so as to not overide) the PHP FILETER error message.
     */
    protected function phpFilterErrToMesg(array $phpFilterResults, array $phpFilterErrMsgs, array &$errors,  array &$testResults)
    {        
        foreach($phpFilterResults as $key => $value)
        {
            if($value !== false)
            {
                $testResults[$key] = true;
            }
            else
            {
                $errors[$key]  = $phpFilterErrMsgs[$key];   //Here's wher the error message is transfered.
                $testResults[$key] = false;
            }
        }
        
        //Free up resources.
        $phpFilterResults = NULL;
        $phpFilterErrMsgs = NULL;
        unset($phpFilterResults, $phpFilterErrMsgs);
        return;
    }
    
    
    /**************Core form input validation test methods.********************/
    /**
     *These methods do the actual work of testing input values, typically from
     * an HTML form. 
     * 
     * Phase 1: 
     * 
     * Datatype testing, magnitude/length testing, range checking, and possibly pattern matching (strings).
     * A serpentine of ctype function are used to add another layer to my defense in depth stategy.
     * 
     * The method validateInput() is programmed by the values of a $validationMetaArray
     * to run either stringTest(), integerTest(), or floatTest() on each field.
     * 
     * Phase 2:
     * 
     * Again, as designated by the $validationMetarray, a value may be the empty string, anything,
     * a direct match with some pre-planned value, or it must be a directy match
     * within a range of values (very useful for selection lists and radio buttons.
     */

     /**
      * Phase 2 validation methods.
      * 
      * A method for doing comparisons to specific values, ranges of values,
      * and more. Runs after a string, integer, or float test. 
      */
    protected function matchingTest($input, $noEmptyString, $specificValue, $rangeOfValues, &$errorMessage)
    {        
        /*Begin comparison testing.*/
        if($this->identical($specificValue, false) && $this->identical($rangeOfValues, NULL) && $this->identical($input, '')) //$input must be a non-empty string.
        {
            if(!$noEmptyString)  //If an empty string is allowed.
            {
                return true;
            }
            else
            {
               $errorMessage = 'Must be filled in!';
            }
        }
        elseif($this->identical($specificValue, false)  && $this->identical($rangeOfValues, NULL) && ($input !== ''))
        {   
            return true;
        }
        elseif((is_string($specificValue) || is_int($specificValue) || is_float($specificValue)) && $this->identical($rangeOfValues, NULL))
        {            
            if($this->identical($input, $specificValue)) //Input must strictly match a specific value.
            {
                return true;
            }
            
            $errorMessage = 'Bad match.';
        }
        elseif($this->identical($specificValue, false) && is_array($rangeOfValues) && !empty($rangeOfValues))  //Input must be one in a range of values.
        {
            if(in_array($input, $rangeOfValues, true)) //Input must strictly match a value in the array.
            {
                return true;
            }
            
            $errorMessage = 'Invalid option!';
        }
        else
        {
            $errorMessage = 'Invalid input!';
        }
        
        return false;
    }
    
    
    /**
     * Phase 1 validation methods.
     */

    /**
     * A method for doing floating point value tests.
     */
    protected function floatTest($input, $float, $min, $max, $pattern, &$errorMessage)
    {
        if(is_float($float))                                           //Test data type.
        {
            if($input !== (string)$float)                              //Convert $input into a string to see if it matches original input.
            {
                $errorMessage = 'Invalid input! (Not an option)';
            }
            elseif(preg_match($pattern, $input) === 0)                //Regular expression test.
            {
                $errorMessage = 'Invalid input! (Bad number format)';
            }
            elseif($input < $min)                                     //Test against minimum value.
            {
                $errorMessage = 'Invalid selection! (too low)';
            } 
            elseif($input > $max)                                     //Test against maximum value.
            {
                $errorMessage = 'Invalid selection! (too high)';
            }
            else
            {
                $errorMessage = '';                                  //The erroor message is the empty string.
            }
        }
        else
        {
            $errorMessage = 'Invalid data type!';
        }
    }
    
    /**
     * A method for doing integer value tests.
     */
    protected function integerTest($input, $int, $min, $max, $pattern, &$errorMessage)
    {
        if(is_int($int))                                     //Test data type.
        {
            
            if($input !== (string) $int)                     //Convert $int into a string to see if it matches original input.
            {
                $errorMessage = 'Invalid input! (fake value)';
            }
            elseif(preg_match($pattern, $input) === 0)       //Regular Expression Test
            {
                $errorMessage = 'Invalid input! (Bad number format)';
            }
            elseif($int < $min)                              //Test against minimum value.
            {
                $errorMessage = 'Invalid selection! (too low)';
            } 
            elseif($int > $max)                              //Test against maximum value.
            {
                $errorMessage = 'Invalid selection! (too high)';
            } 
            else
            {
                $errorMessage = '';                         //The erroor message is the empty string.
            }
        }
        else
        {
            $errorMessage = 'Invalid data type!';
        }
    }
    
    /**
     * A method for doing string value tests.
     * A place where whitelisting regular expressions are applied.
     */
    protected function stringTest($input, $kind, $length, $min, $max, $pattern, &$errorMessage)
    {     
        //Because some fields are optional.
        if($this->identical(mb_strpos($kind, 'opt'), 0))
        {
            if($this->identical($input, ''))
            {
                $errorMessage = '';
                return;
            }
            else
            {
                $kind = substr($kind, 3); //Grab the sring after the sub-string, opt.
            }
        }
        
        //Call ctype functions based on 'kind'
        if(((($kind === 'path') || ($kind === 'url') || ($kind === 'email') || ($kind === 'phone') || ($kind === 'ccode') || ($kind === 'ipAddress') || ($kind === 'captcha') || ($kind === 'state') || ($kind === 'zip')) && ctype_graph($input)) ||
            ((($kind === 'name') || ($kind === 'password') || ($kind === 'title') || ($kind === 'userAgent') || ($kind === 'text') || ($kind === 'company') || ($kind === 'address') || ($kind === 'city') || ($kind === 'country') || ($kind === 'cityState')) && ctype_print($input)) ||
            ((($kind === 'answer') || ($kind === 'digest')) && ctype_graph($input) && ctype_alnum($input)) ||
            ((($kind === 'word') && ctype_graph($input) && ctype_alpha($input))) ||
            ((($kind === 'extension')) && ctype_graph($input) && ctype_digit($input)) ||
            (($kind === 'composite')))
        {
            if($length < $min)                                                //Test string against minimum length.
            {
                $errorMessage = 'Too few characters! ('.$min.' min)';
            }
            elseif($length > $max)                                           //Test string against maximum length.
            {
                $errorMessage = 'Too many characters! ('.$max.' max)';
            }
            elseif(preg_match($pattern, $input) === 0)                       //Test string's pattern with a regular expression.
            {
                $errorMessage = 'Invalid format!';
            }
            else
            {
                $errorMessage = '';                                          //The erroor message is the empty string.
            }
        }
        else
        {
            $errorMessage = 'Invalid entry!';
        }
        
        return;
    }
    
    /**
     * Input validation driver/controller.
     */
    protected function validateInput(&$input, $kind, $type, $min, $max, $pattern, $noEmptyString = true, $specificValue = false, array $rangeOfValues = NULL, &$errorMessage = NULL)
    {
        $tempVar = NULL;
        $length  = mb_strlen($input);
        
        if($this->equal($type,'string') && is_string($input))
        {   
            $tempVar = $input;
            $this->stringTest($input, $kind, $length, $min, $max, $pattern, $errorMessage);
        }
        elseif($this->equal($type,'int') && ctype_graph($input) && ctype_digit($input) && is_int((int) $input))  //Remember, integers include zero and negative numbers!!
        {
            $tempVar = (int) $input;  //Cast string to integer datatype
            $this->integerTest($input, $tempVar, $min, $max, $pattern, $errorMessage);

        }
        elseif($this->equal($type,'float') && ctype_graph($input) && is_numeric($input) && is_float((float) $input))
        {
            $tempVar = (float) $input;
            $this->floatTest($input, $tempVar, $min, $max, $pattern, $errorMessage);
        }
        else
        {
            $errorMessage = 'Invalid data entered!';
        }
        
        //A null error message indicates that all previous tests have passed.
        if($this->equal($errorMessage, '') && ($this->matchingTest($tempVar, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage)))
        {
            return true;
        }
        
        return false;
    }
    
    /**************************************************************************/
    
    
    /**
     * This method is the driver of custom validtion.
     * It's main job is to call **Variable Methods**, as seen above,
     * and assign TRUE or FALSE to the appropriate element
     * in the $testResultsArray.
     * 
     * Needa a bit of refactoring, but it does work with two
     * dimensional arrays, too. Probably could come up with
     * a recursive solution.
     */
    protected function coreValidatorLogic()  //Called from within a sub-class's myValidator() method after PHP FILTER tests.
    {
        foreach($this->filteredInputArray as $key => &$value)
        {   
            if($this->testResultsArray[$key] === true) //Only check the ones that passed the PHP Filter validation.
            {
                if(is_scalar($value)) //Go this way for single values.
                {
                    if($this->$key($value, $this->validationMetaArray[$key], $this->errorMessagesArray[$key])) //Execute the "Variable method"
                    {
                        $this->testResultsArray[$key] = true;
                    }
                    else
                    {
                        $this->testResultsArray[$key] = false;
                    }

                    $this->validationMetaArray[$key] = NULL;
                    unset($this->validationMetaArray[$key]);
                }
                else // Go this way for arrays
                {
                    foreach($value as $subKey => $subValue)
                    {
                        if($this->$subKey($subValue, $this->validationMetaArray[$subKey], $this->errorMessagesArray[$subKey]))
                        {
                            $this->testResultsArray[$subKey] = true;
                        }
                        else
                        {
                            $this->testResultsArray[$subKey] = false;
                        }

                        $this->validationMetaArray[$subKey] = NULL;
                        unset($this->validationMetaArray[$subKey]);
                    }
                }
            }
        }

        $this->validationMetaArray = NULL;
        unset($this->validationMetaArray);
    }
    
    
    /********     Generally universal field validator methods. **************/
    /**
     * Obviously, every page does not have the need to validate captchas
     * and tokens, but it's better than putting them in traits. Howwever, I do
     * use trains when I need to factor code horizaontally, that really, truly,
     * should not be part of a super-class. Since this is a validator, I feel this
     * is alright.
     * 
     * Sub-classes have *variable methods* defined for unique fields, or they use traits to
     * acquire the *varialbe methods* they need.
     */

    /**
     * Validates the main form token on a web page.
     * If there is more than one form on a page, the page's
     * sub-class validator will need to define its own
     * **variable methods** for them.
     * 
    
     * Validates <input type="hidden" name="token">
     */
    protected function token($string, array $validationMetaArray, &$errorMessage)  //A token that does not validate is a security issue.
    {
        extract($validationMetaArray);  //$kind, $type, $min, $pattern,  $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern,  $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }
    
    /**
     * Validates a form's captcha. If there is more than one captacha on a page (????),
     * the sub-class will have to define *variable methods for the extra ones*. I have
     * never seen that, but that's what would have to happen. :-)
     */
    protected function captcha($string, array $validationMetaArray, &$errorMessage) //A captcha that does not validate is a security issue.
    {
        extract($validationMetaArray);  //$kind, $type, $min, $pattern,  $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }
  
    /**************************************************************************/
    /**************************************************************************/    
    
    /*Public Methods*/
    public function validate()  //This is what gets the ball rolling.
    {
        if($this->myValidator())
        {
            return true;
        }
        
        return false;
    }
}


/**
 * A class for validating some INPUT_SERVER values before using them.
 */
class ServerValidator extends Validator
{
    /*Properties*/
    
    /*****HTTP_REFEREER Validation*******/
    private $filteredExtElement = NULL;
    private $refererUrl         = NULL;       //Only gets a value during a good http POST request.

    //The restrictions have been loosed for code sample purposes.
    private $httpRefererValidationMetaArray = ['kind' => 'url', 'type' => 'string', 'min' => 1, 'max' => 256, 'pattern' => '#https??://[a-z0-9:./?=&+-]{1,256}?#', 'noEmptyString' => true, 'specificValue' =>  false, 'rangeOfValues' => NULL];
    /************************************/
    
    private $httpHost      = NULL;
    private $requestMethod = NULL;
    private $requestUri    = NULL;
    private $userAgent     = NULL;
    private $userIp        = NULL;

    //Blacklisting reqular expressions.
    private $httpHostRegex      = '/(?>\A[^\p{C}0-9 %^!#$%&\'*+\/=?^`\{\|\}~\]\[\"\(\),:;\<\>]+?\z){1}?/u';    
    private $httpUserAgentRegex = '/(?>[^\p{C}]+?)+?/u';
    private $requestMethodRegex = '/(?>[^\p{C}]+?)+?/u';
    private $requestUriRegex    = '/(?>[^\p{C}]+?)+?/u';

    public function __construct(array $filteredInput)
    {
        $phpFVA = [
                        'HTTP_HOST'       => ['filter'  => FILTER_VALIDATE_REGEXP,
                                              'flags'   => FILTER_REQUIRE_SCALAR,
                                              'options' => ['regexp' => $this->httpHostRegex]],
                        'HTTP_USER_AGENT' => ['filter'  => FILTER_VALIDATE_REGEXP,
                                              'flags'   => FILTER_REQUIRE_SCALAR,
                                              'options' => ['regexp' => $this->httpUserAgentRegex]],
                        'REMOTE_ADDR'     => ['filter'  => FILTER_VALIDATE_IP, 
                                              'flags'   => FILTER_REQUIRE_SCALAR | FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6],
                        'REQUEST_METHOD'  => ['filter'  => FILTER_VALIDATE_REGEXP,
                                              'flags'   => FILTER_REQUIRE_SCALAR,
                                              'options' => ['regexp' => $this->requestMethodRegex]],
                        'REQUEST_URI'     => ['filter'  => FILTER_VALIDATE_REGEXP,
                                              'flags'   => FILTER_REQUIRE_SCALAR,
                                              'options' => ['regexp' => $this->requestUriRegex]]
                  ];

        $phpFEMA = [
                        'HTTP_HOST'       => 'Bad URL for HTTP_HOST.',
                        'HTTP_USER_AGENT' => 'Bad string for HTTP_USER_AGENT.',
                        'REMOTE_ADDR'     => 'Bad IP address for REMOTE_ADDR.',  //Or, possibly an IPV6 address
                        'REQUEST_METHOD'  => 'Bad string for REQUEST_METHOD',
                        'REQUEST_URI'     => 'Bad string for REQUEST_URI',
                        'HTTP_REFERER'    => 'Bad URL for HTTP_REFERER.'
                   ];

        $validationMA = [
                            'HTTP_HOST'       => ['kind' => 'url', 'type' => 'string', 'min' => 1, 'max' => 50, 'pattern' => '/\A(?>[a-z.]){1,50}?\z/iu', 'noEmptyString' => true, 'specificValue' => false, 'rangeOfValues' => NULL],
                            'HTTP_USER_AGENT' => ['kind' => 'userAgent', 'type' => 'string', 'min' => 28, 'max' => 512, 'pattern' => '/(?>Chrome|AppleWebKit|Safari|Silk|MSIE|Trident|Firefox|Gecko|Presto|Opera|Mozilla|Baidu|Google|Bing|Yahoo){1}?/iu', 'noEmptyString' => true, 'specificValue' => false, 'rangeOfValues' => NULL], 
                            'REMOTE_ADDR'     => ['kind' => 'ipAddress', 'type' => 'string', 'min' => 3, 'max' => 15, 'pattern' => '/\A(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\z/u', 'noEmptyString' => true, 'specificValue' => false, 'rangeOfValues' => NULL],
                            'REQUEST_METHOD'  => ['kind' => 'word', 'type' => 'string', 'min' => 3, 'max' => 4, 'pattern' => '/(?>\AGET|POST\z){1}?/u', 'noEmptyString' => true, 'specificValue' => false, 'rangeOfValues' => ['GET', 'POST']],
                            'REQUEST_URI'     => ['kind' => 'path', 'type' => 'string', 'min' => 1, 'max' => 256, 'pattern' => '/(?>\A\/{1}?[A-Za-z0-9.?=&\/+-]{0,255}?\z)/u', 'noEmptyString' => true, 'specificValue' => false, 'rangeOfValues' => NULL]
                        ];

        parent::__construct($phpFVA, $phpFEMA, $validationMA, $filteredInput);
    }
    
    /*Mutators*/
    public function setFilteredExtElement($value)
    {
        if(!is_scalar($value))
        {
            throw new InvalidArgumentException('The validation $value must be scalar.');
        }
        
        if(!is_string($value))
        {
            throw new InvalidArgumentException('The validation $value must be a string');
        }
        
        $this->filteredExtElement = $value;
    }
    
    private function setHttpHost()
    {
        $this->httpHost = $this->filteredInputArray['HTTP_HOST'];
    }
    
    private function setRefererUrl()
    {
        $this->refererUrl = $this->filteredExtElement;
    }
    
    private function setRequestMethod()
    {
        $this->requestMethod = $this->filteredInputArray['REQUEST_METHOD'];
    }
    
    private function setRequestUri()
    {
        $this->requestUri = $this->filteredInputArray['REQUEST_URI'];
    }
    
    private function setUserAgent()
    {
        $this->userAgent = $this->filteredInputArray['HTTP_USER_AGENT'];
    }
    
    private function setUserIp()
    {
        $this->userIp = $this->filteredInputArray['REMOTE_ADDR'];
    }

    
    /*HTTP Request Handling Methods*/
    private function saveGetRequestIdentity()
    {
        $_SESSION['userIp']    = $this->userIp;
        $_SESSION['userAgent'] = $this->userAgent;
    }

    public function isGET()
    {
        if($this->requestMethod === 'GET')
        {
            $this->saveGetRequestIdentity();
            return true;
        }
            
        return false;
    }
    
    private function hasTokenTimeLeft()
    {
        if(isset($_SESSION['tokenExpireTime']) && (time() < $_SESSION['tokenExpireTime']))
        {
            return true;
        }
        
        throw new SecurityException("Token time has expired for this POST request.");
    }
    
    private function hasSameGETandPOSTIdentities()
    {
        if(($this->userIp === $_SESSION['userIp']) &&
            ($this->userAgent === $_SESSION['userAgent']))
        {
            return true;
        }
        
        return false;
    }
    
    private function isGoodHttpReferer(Sanitizer $sanitizer)
    {
        //Sanitize an extra scalar value inside of INPUT_SERVER.
        $sanitizer->httpRefererExists();
        $sanitizer->httpRefererHasGoodSize();
        $sanitizer->setExtInputElement('HTTP_REFERER');
        $sanitizer->sanitizeElement();

        //Validate the extra scalar value from INPUT_SERVER.
        $this->setFilteredExtElement($sanitizer->getFilteredExtElement());
        return $this->validateFilteredElement();
    }
    
    public function isPOST(Sanitizer $sanitizer)
    {
        if(($this->requestMethod === 'POST')                &&
                $this->hasTokenTimeLeft()                   &&
                $this->hasSameGETandPOSTIdentities()        &&
                $this->httpHost === filter_input(INPUT_SERVER, 'SERVER_NAME') &&  //SERVER_NAME is supplied by APACHE
                $this->isGoodHttpReferer($sanitizer)
           )
        {
            return true;
        }
            
        return false;
    }
    

    /*Helper Methods*/    
    protected function isVoidInput()
    {
        if(($this->filteredInputArray['HTTP_HOST'] === '')            ||
                ($this->filteredInputArray['HTTP_USER_AGENT'] === '') ||
                ($this->filteredInputArray['REMOTE_ADDR'] === '')     ||
                ($this->filteredInputArray['REQUEST_METHOD'] === '')  ||
                ($this->filteredInputArray['REQUEST_URI'] === ''))
        {
            return true;
        }
        
        return false;
    }

    private function setServerProperties()
    {
        $this->setHttpHost();
        $this->setRequestMethod();
        $this->setRequestUri();
        $this->setUserAgent();
        $this->setUserIp();
        
        if(isset($this->httpHost, $this->requestMethod, $this->requestUri, $this->userAgent, $this->userIp))
        {
            return true;
        }

        return false;
    }

    private function freeUpResources()  //This should also kill the session.
    {
        //Free up resources.
        $_SERVER  = NULL;
        $_GET     = NULL;
        $_POST    = NULL;
        $_FILES   = NULL;
        $_COOKIE  = NULL;
        $_SESSION = NULL;
        $this->filteredInputArray        = NULL;
        $this->testResultsArray          = NULL;
        $this->validationMetaArray       = NULL;
        $this->phpFieldValidatationArray = NULL;
        $this->phpFieldErrMsgsArray      = NULL;
        unset($this->filteredInputArray, $this->testResultsArray, $this->validationMetaArray, $this->phpFieldValidationArray, $this->phpFieldErrMsgsArray);
    }

    protected function myValidator()
    {       
        //Blank http request submission test.
        if($this->isVoidInput())
        {
            $this->freeUpResources();
            throw new ValidationException('The HTTP request had void values in INPUT_SERVER. Essential information missing.');
        }

        $phpFilterResults = [];
        
        //Use PHP FILTER functions to validate input.
        $phpFilterResults = filter_var_array($this->filteredInputArray, $this->phpFieldValidationArray, true);
        
        //Check and interpret PHP FILTER validation results.
        $this->phpFilterErrToMesg($phpFilterResults, $this->phpFieldErrMsgsArray, $this->errorMessagesArray, $this->testResultsArray);
        
        //Check for errors. $_SERVER validation errors are FATAL.
        if(in_array(false, $phpFilterResults, true))
        {
            //Free up resources.
            $this->freeUpResources();
            throw new ValidationException('The PHP filter validator for INPUT_SERVER has failed. ' . print_r($this->errorMessagesArray, true));
        }
        
        //Free up resources.
        $this->phpFieldErrMsgsArray = NULL;
        $phpFilterResults           = NULL;
        unset($this->phpFieldErrMsgsArray, $phpFilterResults);
        
        //This wrapper method calls "variable functions" that validate each field.
        $this->coreValidatorLogic();
        
        //Check for errors. $_SERVER validation errors are FATAL.     
        if(!in_array(false, $this->testResultsArray, true) && $this->setServerProperties())
        {
            $this->filteredInputArray        = NULL;
            $this->testResultsArray          = NULL;
            $this->validationMetaArray       = NULL;
            $this->phpFieldValidatationArray = NULL;
            $this->phpFieldErrMsgsArray      = NULL;
            unset($this->filteredInputArray, $this->testResultsArray, $this->validationMetaArray, $this->phpFieldValidationArray, $this->phpFieldErrMsgsArray);
            return true; //VALIDATION SUCCESS!!!!
        }

        $this->freeUpResources();
        
        //In other validators, this line would say 'return false'. $_SERVER validation errors are fatal!
        throw new ValidationException('The HTTP request did not validate.' . print_r($this->errorMessagesArray, true));
    }
    
    public function validateFilteredElement()
    {        
        if($this->filteredExtElement === '')  //VOID INPUT TEST
        {
            throw new ValidationException("The HTTP_REFERER cannot be the empty string for a valid form (POST) submission.");
        }
        
        //Use PHP Filter Validator.
        if(!filter_var($this->filteredExtElement, FILTER_VALIDATE_URL, FILTER_REQUIRE_SCALAR))
        {
            $this->errorMessagesArray['HTTP_REFERER'] = $this->phpFieldErrMsgsArray ['HTTP_REFERER'];
            throw new ValidationException("The PHP validator for $this->filteredExtElement has failed.\n {$this->errorMessagesArray['HTTP_REFERER']}");
        }
              
        //Use personal validator.
        if(!$this->HTTP_REFERER($this->filteredExtElement, $this->httpRefererValidationMetaArray, $this->errorMessagesArray['HTTP_REFERER']))
        {
            throw new ValidationException("The HTTP_REFERER is invalid.\n" . print_r($this->errorMessagesArray['HTTP_REFERER'], true));
        }

        $this->setRefererUrl();
        return true;
    }

    
    /*Field Validator Functions*/
    protected function HTTP_HOST($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }
    
    private function getRefererHostname($url) //Used in the fucntion below. //HEY CHANGE TO HTTPS BEFORE YOU GO LIVE!!!!!!!!!!
    {
        $scheme = 'http://';    //HEY CHANGE TO HTTPS BEFORE YOU GO LIVE!!!!!!!!!!
        
        do
        {
            if(mb_strpos($url, $scheme) === 0 || mb_strpos($url, $scheme))  //Find 'https://', if it exists.
            {
                $url = trim(str_replace($scheme, '', $url));          //Remove https://
            }
            else
            {
                break;
            }
        } while(1);

        if(mb_strpos($url, '/') > 0)                  //Find '/', if it exists.
        {
            return trim(mb_strstr($url, '/', true));  //Return everything before the first occurance of '/'.
        }  
    }

    protected function HTTP_REFERER($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            if($this->getRefererHostname($string) === $this->httpHost)  //HTTP_HOST has already been checked against SERVER_NAME
            {
                return true;
            }
            
            $errorMessage = "The hostname in the HTTP_REFERER does not match the one found in HTTP_HOST and SERVER_NAME.";
        }
        
        return false;
    }
    
    protected function HTTP_USER_AGENT($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }

    protected function REMOTE_ADDR($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValuess

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }
    
    protected function REQUEST_METHOD($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $max, $pattern, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }

    protected function REQUEST_URI($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }
}


/**
 *A class for working with multi-byte strings.
 */
class String
{
    /* Properties */
    
    //Regular Expressions
    private $mbWhitespace   = '[\p{C} ]+|[\s\x0B\0]+';    //UTF-8, Unicode
    private $pregWhitespace = '/[\p{C} ]+|[\s\x0B\0]+/u'; //UTF-8, Unicode
    
    /*Constructor*/
    public function __construct($encoding) 
    {   
        $this->isValidMBEncoding($encoding);
        $this->isValidMBRegexEncoding($encoding);
    }

    
    /* Validators */
    private function isValidString($string)
    {
        if(!is_string($string))
        {
            throw new InvalidArgumentException("$string is NOT a string!!!");
        }
        
        return;
    }
    
    private function isValidMBEncoding($encoding)
    {
        if(!mb_internal_encoding($encoding))
        {
            throw new InvalidArgumentException("$encoding is not a valid encoding that PHP Multibyte String recognizes.");
        }
        
        return;
    }
    
    private function isValidMBRegexEncoding($encoding)
    {
        if(!mb_regex_encoding($encoding))
        {
            throw new InvalidArgumentException("$encoding is not a valid regular expression encoding that PHP Multibyte String recognizes.");
        }
        
        return;
    }
    
    private function isValidSplitOutput(array $tokens)
    {
        if(count($tokens) > 0)
        {
            return $tokens;
        }
        
        throw new UnexpectedValueException("The wrapped function preg_split() did not return an array of 1, or more, strings.");
    }

    
    /**
     * Splits email address by the @ symbol.
     * Gets the local and domain parts of an e-mail address.
     */    
    public function getEmailAddressParts($string)
    {
        $this->isValidString($string);
        return mb_split('@', $string, 2);
    }
    
    /**
     * Splits email address by the @ symbol.
     * Gets the first part of an e-mail address.
     */    
    public function getEmailLocalPart($string)
    {   
        $this->isValidString($string);
        return mb_split('@', $string, 2)[0];
    }
    
    /**
     * Splits email address by the @ symbol.
     * Gets the second part of an email address.
     */
    public function getEmailDomainPart($string)
    {        
        $this->isValidString($string);
        return mb_split('@', $string, 2)[1];
    }
    
    /**
     * UTF-8 is the default character encoding as of PHP 5.6.
     * You may need to set default_charset in your php.ini to UTF-8.
     * Alternatively, you can use ini_set() to set your default_charset.
     * 
     * I bet some people used '\s' for white space. :-)
     * 
     * http://php.net/manual/en/function.trim.php <--Provides a handy definition of whitespace.
     * 
     * Boom. (Mic drop. Play the Vince Carter 2000 NBA Dunk Contets video! (1:51) ---> https://www.youtube.com/watch?v=WbzBIvXwqEU ). 
     */
    public function mbWhitespaceSplit($string)
    {        
        $this->isValidString($string);
        return $this->isValidSplitOutput(mb_split($this->mbWhitespace, $string, -1));  //Should return an array of 1, or more, elements. 
    }
    
    /**
     * UTF-8 is the default character encoding as of PHP 5.6.
     * You may need to set default_charset in your php.ini to UTF-8.
     * Alternatively, you can use ini_set() to set your default_charset.
     * 
     * I bet some people used '\s' for white space. :-)
     * 
     * http://php.net/manual/en/function.trim.php <--Provides a handy definition of whitespace.
     * 
     * Boom. (Mic drop. Play the Vince Carter 2000 NBA Dunk Contets video! (1:51) ---> https://www.youtube.com/watch?v=WbzBIvXwqEU ). 
     */
    public function pregWhitespaceSplit($string)
    {
        return $this->isValidSplitOutput(preg_spilt($this->pregWhitespace, $string, -1));  //Should return an array of 1, or more, elements.        
    }
}


/**
 * A class for validating email addresses along many dimensions.
 */
class EmailValidator extends Validator
{
    /* Properties */
    private $string = NULL;
    
    /*Constructor*/
    public function __construct(String $string) 
    {
        /*******************************************************
         * Custom validation instructions for e-mail addresses.*
         *******************************************************/
       
        //Whitelisting regular expressions is used here: pattern => '//'
        //Validation Meta Array Note: The pattern element wrongly allows consecutive periods. Use defense in depth until fixed.
        $validationMA = ['email' => ['kind' => 'email', 'type' => 'string', 'min' => 6, 'max' => 254, 'pattern' => '/(?>\A[A-Za-z0-9_-][A-Za-z0-9_.-]{0,62}?[A-Za-z0-9_-]{0,1}@{1}?(?:(?:[A-Za-z0-9]{1}?){1}?(?:[A-Za-z0-9.-]{0,61}?[A-Za-z0-9]{1}?){0,1}?){1,127}?\.{1}?[a-z]{2,20}?\z){1}?/u', 'noEmptyString' => true, 'specificValue' =>  false, 'rangeOfValues' => NULL]];
       
        parent::__construct([], [], $validationMA, []);
        $this->string = $string;
    }
    
    
    /* Validators*/
    private function isArrayOfStrings(array $strings)
    {
        foreach($strings as $emailAddress)
        {
            if(!is_string($emailAddress))
            {
                throw new InvalidArgumentException("All elements of the input array must be of type string.");
            }
        }

        return $strings;
    }
    
    /* Mutators */
    private function setPHPFilterInstructions()
    {        
        for($i = 1, $length = count($this->filteredInputArray); $i <= $length; ++$i)
        {
            $index = " {$i}";
            $this->phpFieldValidationArray[$index] = ['filter' => FILTER_VALIDATE_EMAIL, 'flags' => FILTER_REQUIRE_SCALAR];
            $this->phpFieldErrMsgsArray[$index] = ['email' => 'Improperly formatted e-mail address.'];
        }
        
        return;
    }

    public function setFilteredInputArray(array $emailAddresses)
    {
        $this->filteredInputArray = $this->isArrayOfStrings($emailAddresses);
        $this->setPHPFilterInstructions();
    }
    

    /**
     * Checks for empty strings.
     */
    protected function isVoidInput()
    {        
        foreach($this->filteredInputArray as $key => $emailAddress)
        {
            if($emailAddress === '')
            {
                $this->testResultsArray[$key] = false;
                $this->errorMessagesArray[$key] = "Empty string at index {$key}.";
            }
        }

        return;
    }


    /**
     * Saves the list of all the domains found during processing.
     */
    private function translateValidatedInput()
    {
        $this->translatedInputArray = $this->filteredInputArray;
        return;
    }

    
    /**
     * The overriding, core logic for vailidating e-mail address.
     * A counter controlled version of the core validation logic.
     * Why counter controlled? There is no way to know how many
     * e-mail address there will be ahead of time.
     */
    protected function coreValidatorLogic()
    {
        foreach($this->filteredInputArray as $key => $emailAddress)
        {
            if($this->testResultsArray[$key] === true) //Because we do not want to override a PHP Filter error condition.
            {
                if($this->email($this->filteredInputArray[$key], $this->validationMetaArray['email'], $this->errorMessagesArray[$key]))
                {
                    $this->testResultsArray[$key] = true;
                }
                else
                {
                    $this->testResultsArray[$key] = false;  
                }
            }
        }
        
        $this->validationMetaArray = NULL;
        unset($this->validationMetaArray);
        return;
    }
        
    /**
     * A method that looks for DNS MX records.
     * Returns array of bad domains.
     */
    private function mxDNSPing(array $uniqueDomains)
    {   
        $badDomains = [];
        
        foreach($uniqueDomains as $key => $domain)
        {
            if(!checkdnsrr($domain, 'MX'))
            {
                $this->testResultsArray[$key] = false;
                $this->errorMessagesArray[$key] = 'No DNS MX records found.';
                $badDomains[$key] = $domain;
            }
        }
        
        return $badDomains;
    }
    
    /**
     * A method that returns an array of unique domain names.
     */
    private function removeDuplicateDomains(array $domains)
    {
        /**
         * array_unique() sorts the values, but preserves the indexes.
         * Then, it keeps the 1st unique value of each group. The input array is unaltered.
         */

        return array_unique($domains, SORT_STRING);
    }
    
    /**
     * A method that returns an array of bad email domains using DNS.
     */
    private function getBadEmailDomains(array $domains)
    {
        return $this->mxDNSPing($this->removeDuplicateDomains($domains));
    }
    
    /**
     * A method that returns an array of email domains.
     */
    private function getGoodEmailDomains()   //Verify email address domains through DNS.
    {   
        $domains = [];
        
        foreach($this->filteredInputArray as $key => $emailAddress)
        {
            //Get the domains of good email addresses only!
            if($this->testResultsArray[$key] === true)
            {
                $domains[$key] = $this->string->getEmailDomainPart($emailAddress);
            }
        }
         
        return $domains; //This includes duplicate domains!
    }

    /**
     * A method that manages DNS verification of e-mail domains.
     * @returns array
     */
    private function secondaryEmailValidationLogic()
    {
        $goodDomains = $this->getGoodEmailDomains();
        $badDomains  = $this->getBadEmailDomains($goodDomains);

        foreach($goodDomains as $key => &$domain)
        {
            if(in_array($domain, $badDomains, true))
            {
               $this->testResultsArray[$key] = false;
               $this->errorMessagesArray[$key] = 'No DNS MX records found.';
               unset($domain);
               echo 'UNSET';
            }
        }

        $this->filteredInputArray = $goodDomains;
    }

    /**
     *A method that servers as the "main line" for validating e-mail addresses.
     *It is invoked by the super-class method, Validator::validate().
     */
    protected function myValidator()
    {   
        $phpFilterResults = [];  //Save PHP Filter test results, which can be 1) a good value, 2) false, or 3) NULL for each array element.        
        $this->isVoidInput();    //Checks for empty strings.

        /*******************Use PHP validation functions.**********************/
        
        //Use PHP FILTER functions to validate input.
        $phpFilterResults = filter_var_array($this->filteredInputArray, $this->phpFieldValidationArray, true);
        
        //Check and interpret PHP FILTER validation results.
        $this->phpFilterErrToMesg($phpFilterResults, $this->phpFieldErrMsgsArray, $this->errorMessagesArray, $this->testResultsArray);
        
        //Free up resources.
        $this->phpFieldErrMsgsArray = NULL;
        $phpFilterResults           = NULL;
        unset($this->phpFieldErrMsgsArray, $phpFilterResults);
        
        /*******************Use personal validation methods.*******************/
        
        $this->coreValidatorLogic();                                        //Usee $this->mail() to validate e-mail addresses.
        $this->secondaryEmailValidationLogic(); //Returns an array of good domains.

        /**********************************************************************/
        
        $this->translateValidatedInput(); 
            
        //Free up resources.
        $this->filteredInputArray = NULL;
        unset($this->filteredInputArray);
            
        /**
         * Means that the validator finished successfuly, not that all inputs
         * were infact e-mail addressse.
         */
        return true; 
    }
    
    /**
     * Finds problems with the local or domain parts of an e-mail address.
     */
    private function emailPartProblemFinder($string, &$errorMessage)
    {
        $emailParts = $this->string->getEmailAddressParts($string);

        if(count($emailParts) !== 2)
        {
            $errorMessage = 'Invalid e-mail address!';
        }
        else
        {
            list($localPart, $domain) = $emailParts;
            
            $localLength  = mb_strlen($localPart);
            $domainLength = mb_strlen($domain);

            if($localLength === 0)
            {
                $errorMessage = 'Missing local part of address.';
            }
            elseif($localLength > 64)
            {
                $errorMessage = 'Only 64 characters are alloed before the @ symbol ('.$localLength.' given)';
            }
            elseif(mb_strrpos($string, '.') === ($localLength - 1))
            {
                $errorMessage = 'The local part of an email address cannot end with a period (.).';
            }
            elseif(mb_strpos($string, '..') >= 0)
            {
                $errorMessage = 'The local part of an email address cannot contain consecutive periods (..).';
            }
            elseif($domainLength < 4) //x.yy, is my minimum domain format.
            {
                $errorMessage = 'Domain part < 4 characters. ('.$domainLength.' given)';
            }
            elseif(strlen($domainLength > 253))
            {
                $errorMessage = 'Domain part exceeds 253 characters. ('.$domainLength.' given)';
            }
        }
        
        return;
    }
    
    /**
     * Finds problems with e-mail as a whole.
     */
    private function emailAddressProblemFinder($string, $max, &$errorMessage)
    {
        $length = mb_strlen($string);
        $atSymbolCount = mb_substr_count($string, '@', 'UTF-8');

        if($length === 0)
        {
            return false;    //The reason was already assigned to the error message inside of $this->validateInput()
        }
        elseif($length > 254)
        {
            $errorMessage = 'Exceeds max length ('.$max.' characters)';
        }
        elseif((mb_strpos($string, '@') === 0))
        {
            $errorMessage = 'Cannot start with a @';
        }
        elseif((mb_strrpos($string, '@') === ($length - 1)))
        {
            $errorMessage = 'Cannot end with a @';
        }
        elseif($atSymbolCount > 1)
        {
            $errorMessage = '@ appears '.$atSymbolCount.' times.';
        }
        elseif((mb_strpos($string, '@') === false))
        {
            $errorMessage = 'The @ symbol is missing.';
        }
        elseif(mb_strpos($string, '.') === 0)
        {
            $errorMessage = 'The local part of an email address cannot start with a period (.).';
        }
        else
        {
            $this->emailPartProblemFinder($string, $errorMessage);
        }
        
        return;
    }
    
    /**
     * Validates email addresses..
     */
    private function email($string, array $validationMetaArray, &$errorMessage)
    {        
        extract($validationMetaArray);  //$kind, $type, $min, $pattern, $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern, $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }

        //Attempt to disover why the email address test failed.
        $this->emailAddressProblemFinder($string, $max, $errorMessage);

        return false;
    }
}


/**
 * WARNING: NOT FOR THE FAINT OF HEART!!!
 * http://php.net/manual/en/filter.filters.validate.php
 * 
 * A sub-class that contains input validation methods unique to
 * this page and data specific to validating an HTTP POST on 
 * "the Page." It uses custom and PHP validation techniques.
 * 
 * This class provides validation instructions to its super-class.
 */
class DomainPageValidatorPOST extends Validator     //I know, crazy class name. Roll with it for now. ;-)
{ 
    /* Properties */
    
    //Objects
    private $emailValidator = NULL;  //Used to check if each element of an array is an email addresss.
    private $string = NULL;          //Used when translating validated input.
    
    //Blacklisting, Unicode,  Regular Expressions
    private $compositeStrRegex = '/(?>[^!#$%&\'*+\/=?^`\{\|\}~\]\[\"\(\),:;\<\>]){1}?/u';
    private $listBtnRegex      = '/(?>[^\p{C}0-9 %]){1}?/u';
    private $tokenRegex        = '/(?>[^\p{C}g-z %]){1}?/u';
    
    /*Constructor*/
    public function __construct(EmailValidator $emailValidator, String $string, array $filteredInput) 
    {        
        /****************************************************
         * Validation Instructions for submitted HTML forms.*
         ****************************************************/    
        
        //PHP Field Validation Array
        $phpFVA = [
                    'compositeStr' => ['filter'  => FILTER_VALIDATE_REGEXP,                  //<textarea>
                                       'flags'   => FILTER_REQUIRE_SCALAR,
                                       'options' => ['regexp' => $this->compositeStrRegex]],
                    'listBtn'      => ['filter'  => FILTER_VALIDATE_REGEXP,                  //<button>
                                       'flags'   => FILTER_REQUIRE_SCALAR,
                                       'options' => ['regexp' => $this->listBtnRegex]],
                    'token'        => ['filter'  => FILTER_VALIDATE_REGEXP,                  //<input type="hidden">
                                       'flags'   => FILTER_REQUIRE_SCALAR,
                                       'options' => ['regexp' => $this->tokenRegex]]
                  ];
        
        //PHP Field Error Message Array
        $phpFEMA = [
                    'compositeStr' => 'Illegal data entered! This field only accepts whitespace and the following characters: A-Z, a-z, 0-9, @, _, ., -',
                    'listBtn'      => 'Illegal button data entered! Please use the List Domains button.',
                    'token'        => 'Illegal token data entered! Please use our site to fill out the form.'
                   ];
        

        //Whitelisting, Unicode, regular expressions are used here: pattern => '//'
        //Validation Meta Array
        $validationMA = [
                            'compositeStr' => ['kind' => 'composite', 'type' => 'string', 'min' => 6, 'max' => PHP_INT_MAX, 'pattern' => '/(?>[A-Za-z0-9_.-]{1,64}?@{1}?(?:(?:[A-Za-z0-9]{1}?){1}?(?:[A-Za-z0-9.-]{0,61}?[A-Za-z0-9]{1}?){0,1}?){1,127}?\.{1}?[a-z]{2,20}?[\p{C} \r\n]{0,}){1,}/u', 'noEmptyString' => true, 'specificValue' => false, 'rangeOfValues' => NULL],
                            'listBtn'      => ['kind' => 'word', 'type' => 'string', 'min' => 4, 'max' => 4, 'pattern' => '/(?>\A(?:List){1}?\z){1}?/u', 'noEmptyString' => true, 'specificValue' => 'List', 'rangeOfValues' => NULL],
                            'token'        => ['kind' => 'digest', 'type' => 'string', 'min' => 32, 'max' => 32, 'pattern' => '/(?>\A[a-f0-9]{32}?\z){1}?/u', 'noEmptyString' => true, 'specificValue' => $_SESSION['token'], 'rangeOfValues' => NULL]
                        ];

        parent::__construct($phpFVA, $phpFEMA, $validationMA, $filteredInput);
        $this->emailValidator = $emailValidator;
        $this->string = $string;
    }

    
    /**
     * Blank form sumbission test.
     */
    protected function isVoidInput()
    {        
        if(($this->filteredInputArray['compositeStr'] === '') && 
                ($this->filteredInputArray['listBtn'] === 'List'))
        {   
            $mandatoryFieldsArray = ['compositeStr'];

            //Provide error messages and for mandatory input fields (text, email, url, tel.
            foreach($mandatoryFieldsArray as $value)
            {
                $this->errorMessagesArray[$value] = 'Ha! Did you forget something? ;-)';
                $this->testResultsArray[$value]   = false;
                
                //Free up resources.
                $this->validationMetaArray[$value]       = NULL;
                $this->phpFieldValidatationArray[$value] = NULL;
                $this->phpFieldErrMsgsArray[$value]      = NULL;
                unset($this->validationMetaArray[$value], $this->phpFieldValidatationArray[$value], $this->phpFieldErrMsgsArray[$value]);
            }
            
            $mandatoryFieldsArray = NULL;
            unset($mandatoryFieldsArray);
            
            //Free up resources.
            $this->validationMetaArray       = NULL;
            $this->phpFieldValidatationArray = NULL;
            $this->phpFieldErrMsgsArray      = NULL;
            unset($this->validationMetaArray, $this->phpFieldValidationArray, $this->phpFieldErrMsgsArray);
            return true;
        }
        
        return false;
    }

    
    /**
     * Transfers input to the $Validator::translatedInputArray.
     * If necessary, this method runes and/or conditions information so that
     * it is ready to be used by client code.
     */
    private function translateValidatedInput()
    {
        //Split (on whitespace) the compositeStr into an array of strings.
        $emailAddresses = $this->string->mbWhitespaceSplit($this->filteredInputArray['compositeStr']);
        
        for($i = 1, $length = count($emailAddresses); $i <= $length; ++$i)
        {
            $index = " {$i}";
            $this->translatedInputArray[$index] = $emailAddresses[$i - 1];
        }
        
        $emailAddresses = NULL;
        $this->translatedInputArray['lstBtn'] = NULL;
        $this->translatedInputArray['token']  = NULL;
        unset($emailAddresses, $this->translatedInputArray['lstBtn'], $this->translatedInputArray['token']);
        return;
    }

    private function getAllEmailDomains(array $emailAddresses)
    {
        $domains = [];
        
        for($i = 0, $length = count($emailAddresses); $i < $length; ++$i)
        {
            $domains[$i] = $this->string->getEmailDomainPart($emailAddresses[$i]);
        }

        return $domains;
    }
    
    private function removeDuplicateDomains(array $domains)
    {
        return array_unique($domains, SORT_STRING);
    }
    
    /**
     * A method that removes malformed e-mail address from an array.
     * Only runs after getting test results back from the e-mail validator.
     */
    private function pruneTranslatedArray(array $emailTestResults)
    {
        for($i = 0, $length = count($this->translatedInputArray); $i < $length; ++$i)
        {
            if($emailTestResults[$i] === false) 
            {
                unset($this->translatedInputArray[$i]);
            }
        }
        
        return;
    }
    
    private function isGoodEmailValidatorReturnData(array $goodDomains)
    {
        if(count($goodDomains) > 0)
        {
            return true;
        }
        
        $this->testResultsArray['compositeStr'] = false;
        $this->errorMessagesArray['compositeStr'] = 'Please enter real e-mail addresses. Thank you!';
        return false;
    }
    
    /**
     *A method that servers as the "main line" for validating "Domain Lister Page" in puts.
     *In voked by the super-class method, Validator::validate().
     */
    protected function myValidator() //The wrapper for the task of validating form inputs.
    {   
        if($this->isVoidInput())     //Blank form submission test.
        {
            return false;            //Somebody is just hitting the form submission button.
        }
        
        $phpFilterResults = [];      //Save PHP Filter test results, which can be 1) a good value, 2) false, or 3) NULL for each array element.

        /*******************Use PHP Filter validation methods.************************/
        
        //Use PHP FILTER functions to validate input.
        $phpFilterResults = filter_var_array($this->filteredInputArray, $this->phpFieldValidationArray, true);

        //Check and interpret PHP FILTER validation results.
        $this->phpFilterErrToMesg($phpFilterResults, $this->phpFieldErrMsgsArray, $this->errorMessagesArray, $this->testResultsArray);
        
        //Free up resources.
        $this->phpFieldErrMsgsArray = NULL;
        $phpFilterResults           = NULL;
        unset($this->phpFieldErrMsgsArray, $phpFilterResults);
        
        /*******************Now use peronsal validation methods.*******************/
        
        //This method calls PHP "variable functions" that validate each inpuy
        //control by HTML 'name' attribute value.
        $this->coreValidatorLogic();

        
        if(!in_array(false, $this->testResultsArray, true))  //If you did not find a failed validation test.
        {            
            $this->translateValidatedInput(); //Convert compositeStr into an array of email addresses.

            $this->emailValidator->setFilteredInputArray($this->translatedInputArray);   //Pass array of strings to $this->emailValidator.
            $this->emailValidator->validate();
            
            $goodDomains = $this->emailValidator->getTranslatedInputArray(); //Returns an array of resolved (DNS), unique domains.
            
            if($this->isGoodEmailValidatorReturnData($goodDomains))
            {
                //Free up resources.
                $this->filteredInputArray = NULL; 
                unset($this->filteredInputArray);
                
                $this->translatedInputArray = $this->removeDuplicateDomains($goodDomains);
                return true;
            }
        }

        /**********************************************************************/
        
        return false;   //Unfortunately, validation failed.
    }
    
    
    //Note: The "token" variable method is inherited from Validator::token.
    
    /**
     * Validates the <button name="listBtn">.
     */
    protected function listBtn($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $pattern,  $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern,  $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }
    

    /**
     * Validates the <textarea name="compositeStr">.
     */
    protected function compositeStr($string, array $validationMetaArray, &$errorMessage)
    {
        extract($validationMetaArray);  //$kind, $type, $min, $pattern,  $noEmptyString, $specificValue, $rangeOfValues

        if($this->validateInput($string, $kind, $type, $min, $max, $pattern,  $noEmptyString, $specificValue, $rangeOfValues, $errorMessage))
        {
            return true;
        }
        
        return false;
    }
}


/**
 * A class ecaping data when it switchs context.
 * This is necessary when displaying user input
 * back to the user agent. I use PDO prepared staements
 * for MySQL.
 */
class Escaper
{
    /* Properties */
    
    /*Constructor*/
    public function __construct() 
    {   
        ;
    }

    /* Private Methods */
    /* Protected Methods */
    

    /* Public Methods */
    public function superHtmlSpecialChars($html)
    {
         return htmlspecialchars($html, ENT_QUOTES | ENT_HTML5, 'UTF-8', false);
    }

    public function superHtmlEntities($html)
    {
        return htmlentities($html, ENT_QUOTES | ENT_HTML5, 'UTF-8', false);
    }

    public function htmlSpecialCharsArray(array &$html)
    {       
        foreach($html as &$value)
        {
            $value = $this->superHtmlSpecialChars($value);
        }
        
        unset($value);
    }
    
    public function htmlEntitiesArray(array &$html)
    {       
        foreach($html as &$value)
        {
            $value = $this->superHtmlEntities($value);
        }
        
        unset($value);
    }
    
    public function urlencodeArray(array $nameAndValue)
    {
        $pairs = [];

        foreach($nameAndValue as $name => $value)
        {
            $pairs[urlencode($name)] = urlencode($value);
        }

        return $pairs;
    }
    
    public function rawurlencodeArray(array $nameAndValue)
    {
        $pairs = [];

        foreach($nameAndValue as $name => $value)
        {
            $pairs[rawurlencode($name)] = rawurlencode($value);
        }

        return $pairs;
    }  
}


/**
 * A class for drawing repetitive HTML elemnts.
 * Its methods frequently use arrays to fill in tables (etc...).
 * 
 * ASCI People: The last three methods are for you. Go to the bottom!
 */
class HTML
{
    /* Properties */

    
    /*Constructor*/
    public function __construct() 
    {   

    }

    /* Private Methods */
    
    /**
     * Sets the class attribute for radios in sticky forms, appropriately.
     */
    private function isNeutralRadio($class, $arrayValue, $checked)
    {
        if(is_int($arrayValue) && is_string($checked)) //When comparing integers.
        {
            if($arrayValue === (int)$checked)
            {
                return $class;
            }
            else
            {
                if($class === 'goodNodes')
                {
                    echo ''; //Will be applied to radio buttons' classes that were not selected, if validation of submitted value is good.
                }
                else
                {
                    echo $class; //The submitted value was bad, so apply the 'badNodes' class to all radio buttons.
                }
                
                return;
            }
        }
        
        if($arrayValue === $checked)
        {
            return $class;
        }
        else
        {
            if($class === 'goodNodes')
            {
                echo '';     //Will be applied to radio buttons' classes that were not selected, if validation of submitted value is good.
            }
            else
            {
                echo $class; //The submitted value was bad, so apply the 'badNodes' class to all radio buttons.
            }
            
            return;
        }
    
    }
    
    
    /**
     * Method for making a selection list sticky.
     */
    private function isSelected($arrayValue, $selected)
    {
        if(is_int($arrayValue) && is_string($selected))
        {
            return ($arrayValue === (int)$selected) ? 'selected="selected" ' : '';
        }
        
        return ($arrayValue === $selected) ? 'selected="selected" ' : '';
    }

    /**
     * Method for making a radio buttons or checkboxes sticky.
     */
    private function isChecked($arrayValue, $checked)
    {
        if(is_int($arrayValue) && is_string($checked))
        {
            return ($arrayValue === (int)$checked) ? 'checked="checked" ' : '';
        }
        
        return ($arrayValue === $checked) ? 'checked="checked" ' : '';
    }
   
    
    /* Protected Methods */
    
    
    /* Public Methods */
    
    /**
     * Set any HTML attribute.
     */
    public function setAttribute($name, $value)
    {
        echo " {$name}=\"{$value}\" ";
    }
    
    /**
     * For <select> options in an indexed array.
     */
    public function drawOptionsArray(array $options, $selected = NULL)
    {
        $lines = [];

        if($selected === NULL)
        {
            foreach($options as $value)
            {
                $lines[] = "<option>$value</option>";
            }
        }
        else
        {
            foreach($options as $value)
            {
                $lines[] = '<option ' .$this->isSelected($value, $selected). ">$value</option>";
            }
        }
        
        echo implode($lines);
    }

    /**
     * For <select> options in an associative array.
     */
    public function drawOptionsAssoc(array $options, $selected = NULL)  //For <select> options in an associative array.
    {
        $lines = [];
        
        if($selected === NULL)
        {
            foreach($options as $key => $value)
            {
                $lines[] = "<option value=\"$key\">$value</option>\n";
            }
        }
        else 
        {
            foreach($options as $key => $value)
            {
                $lines[] = '<option ' .$this->isSelected($key, $selected). "value=\"$key\">$value</option>\n";
            }
        }
        
        echo implode($lines);

    }
    
    /**
     * For <input type=radio> controls.
     */
    public function drawRadioButtons($id, $class, $name, $tabIndex, array $radios, $checked = NULL)
    {   
        if($checked === NULL) //When no radio should be checked by default.
        {
            foreach($radios as $key => $value)
            {
                $idAndKey = $id . $key;
?>
                <input id="<?= $idAndKey; ?>" class="$<?= $class; ?>" name="<?= $name; ?>" type="radio" tabindex="<?= $tabIndex; ?>" title="<?=$key; ?>" value="<?= $value; ?>"><label id="<?= $idAndKey; ?>_" for="<?= $idAndKey; ?>"><?= $key; ?></label>
<?php
                ++$tabIndex;
                echo "\n";
            }
        }
        else //When there is a default radio.
        {
            foreach($radios as $key => $value)
            {
                $idAndKey = $id . $key;
?>
                <input id="<?= $idAndKey; ?>" class="<?= $this->isNeutralRadio($class, $value, $checked) ?>" name="<?= $name; ?>" type="radio" tabindex="<?= $tabIndex; ?>" title="<?= $key; ?>" <?= $this->isChecked($value, $checked)?> value="<?= $value; ?>"><label id="<?= $idAndKey; ?>_" for="<?= $idAndKey; ?>"><?= $key; ?></label>
<?php
                ++$tabIndex;
                echo "\n";
            }
        }
    }
    
    
    /****************ASCI: Recent Method Additions*****************************/
    
    private function drawTableData($data) //Helper
    {
        return "<td>{$data}</td>";
    }
    
    private function drawTableRow($tds)   //Helper
    {
        if(!(is_scalar($tds) || is_array($tds)))
        {
            throw new InvalidArgumentException("Aguments to this method must be scalar or array types.");
        }

        if(is_scalar($tds))  //The row has only one <td>.
        {
            return "<tr>{$this->drawTableData($tds)}<tr>";
        }
        else
        {
            $tdCells = []; //Used when there is more than one <td> in a table row.

            for($i = 0, $length = count($tds); $i < $length; ++$i)
            {
                $tdCells[$i] = $this->drawTableData($tds[$i]);
            }

            return '<tr>' .implode($tdCells). '</tr>';
        }
    }
    
    public function drawTableBody(array $rows)
    {
        $tableRows = [];
        $int = 1;
        
        foreach($rows as $domain)
        {
            $tableRows[] = $this->drawTableRow([$int, $domain]);
            ++$int;
        }
        
        return implode("\n", $tableRows);
    }
}

/**
 * A generic class for doing symmetric encryption and hashing.
 * You Only care about the last method. Cipher::getFormToken()
 */
Class Cipher
{    
    private $clearText = NULL;
    private $cipherText = NULL;

    private $phpFunctions = ['base64_encode', 'base64_decode'];
    
    
    /*Constructor*/
    public function __construct()
    {

    }
    
    
    /*Destructor*/
    public function __destruct() 
    {
        $this->clearText  = '';
        $this->cipherText = '';
    }
    
    
    /*Accessors*/
    public function getClearText()
    {
        return $this->clearText;
    }
    
    public function getCipherText()
    {
        return $this->cipherText;
    }
    
    
    /*Mutators*/
    public function setClearText($clearText)
    {
        $this->clearText = $clearText;
    }
    
    public function setCipherText($cipherText)
    {
        $this->cipherText = $cipherText;
    }
    
    
    /*Magic methods.*/
    public function __call($name, array $args)  //I was just playing with this to see if I could make it work.
    {
        if(function_exists($name) && is_callable($name) && in_array($name, $this->phpFunctions))
        {
            switch($name)
            {
                case 'base64_encode':
                case 'base64_decode':
                    array_unshift($args, $this->cipherText);  //Makes $this->cipherText the 1st argument in the $args array.
                    break;
            }
          
            //return $$name($implode(', ', $args));
            return call_user_func_array($name, $args);
        }
        else
        {
            throw new InvalidArgumentException('The method you called is not valid for this object.');
        }
    }
    
    
    /*Helper methods.*/
    private function createInitVector($cipher, $mode, $source)
    {
        return mcrypt_create_iv(mcrypt_get_iv_size($cipher, $mode), $source);
    }
    
    private function recoverInitVector($ivAndCipherText, $ivSize)
    {
       return substr($ivAndCipherText, 0, $ivSize);
    }

    private function recoverCipherText($ivAndCipherText, $ivSize)
    {
       return substr($ivAndCipherText, $ivSize);
    }
    
    
    /*Public methods.*/
    public function blowfishEncrypt($clearText, $key)
    {        
        $cipher  = MCRYPT_BLOWFISH;
        $mode    = MCRYPT_MODE_CBC;
        $source  = MCRYPT_DEV_URANDOM;
        $iv      = $this->createInitVector($cipher, $mode, $source);

        return $iv . mcrypt_encrypt($cipher, $key, $clearText, $mode, $iv);
    }
    
    public function blowfishDecrypt($ivAndCipherText, $key)
    {
        $cipher  = MCRYPT_BLOWFISH;
        $mode    = MCRYPT_MODE_CBC;

        $ivSize     = mcrypt_get_iv_size($cipher, $mode);
        $iv         = $this->recoverInitVector($ivAndCipherText, $ivSize);
        $cipherText = $this->recoverCipherText($ivAndCipherText, $ivSize);

        return mcrypt_decrypt($cipher, $key, $cipherText, $mode, $iv);
    }

    public function blowfishEncryptArray(array $clearTextArray, $key)
    {
        foreach($clearTextArray as &$string)
        {
            $string = base64_encode($this->blowfishEncrypt($string, $key));
        }
        
        unset($string);
        $cipherTextArray =& $clearTextArray;
        return $cipherTextArray;
    }
  
    public function blowfishDecryptArray(array $cipherTextArray, $key)
    {
        foreach($cipherTextArray as &$string)
        {
            $string = blowfishDecrypt(base64_decode($string), $key);
        }
        
        unset($string);
        $clearTextArray =& $cipherTextArray;
        return $clearTextArray;
    }

    public function superMd5($plainText)
    {
        $salt = (strlen($plainText) * 101) . 'abcDEF~!@#$%^&*()_+UVWxyz';
        return md5($salt . $plainText . uniqid(mt_rand(), true));
    }
    
    public function getFormToken()
    {
        $plainText = uniqid(mt_rand(), true);
        $salt = (strlen($plainText) * 101) . 'abcDEF~!@#$%^&*()_+UVWxyz';
        return md5($salt . $plainText);
    }
}

/**
 * An abstract super class that holds data and methods that can be, or are,
 * vital to a webpage. Sub-classes contain data and methods unique to their
 * respective needs.
 */
abstract class Webpage
{
    /* Properties */
    
    //For pages with <form> tags 
    protected $formToken = NULL;           //Cross-site Request Forgery deterrent.

    //Objects
    protected $escaper   = NULL; //Provides methods for escaping output.
    protected $html      = NULL; //Generates UI HTML elements
    protected $cipher    = NULL; //Performs basic encrpyption duties (such as generating hash/form tokens).
    protected $validator = NULL; //Performs the page validation. 
    
    abstract public function setValidator(Validator $validator);
    
    /* Constructor */
    public function __construct(Escaper $escaper, HTML $html, Cipher $cipher)
    {        
        $this->escaper = $escaper;
        $this->html = $html;
        $this->cipher = $cipher;  
    }
    
    /* Private Methods */    
    public function setFormToken()
    {
        $_SESSION['token'] = NULL;  
        $token = $this->cipher->getFormToken();
        $this->formToken = $token;
        $_SESSION['token'] = $token;  //Save the token for comparison upon form submission.
        $_SESSION['tokenExpireTime'] = time() + (60 * static::FORM_TOKEN_EXPIRE_MINUTES);         //Set the token life time to 30 minutes.
        
        $token = NULL;
        unset($token);
        
        return;
    }
    

    /* Mutators */
    protected function addClass($key, $class)
    {
        $this->classes[$key] = $this->classes[$key] .' '. $class;
    }
    
    protected function setClass($key, $class)
    {
        $this->classes[$key] = $class;
    }
    
    protected function setValue($key, $value)
    {
        $this->values[$key] = $value;
    }
    
    protected function setError($key, $error)
    {
        $this->errors[$key] = $error;
    }
    

    protected function addClasses(array $classes)
    {
        foreach($classes as $key => $value)
        {
            if(isset($this->classes[$key]))
            {
                $this->classes[$key] = $this->classes[$key] .' '. $value;
            }
        }
        
        return;
    }
    
    protected function setClasses(array $classes)
    {
        $this->classes = $classes;
        
        return;
    }
    
    protected function setValues(array $values)
    {
        $this->values = $values;
        
        return;
    }

    protected function setErrors(array $errors)
    {
        $this->errors = $errors;
        
        return;
    }
    
    
    /**
     * Accessors 
     * 
     * These are used heavily to dynamically change the webpage.     
     */
    public function getClass($key)  //Returns CSS information.
    {
        return $this->classes[$key];
    }
    
    public function getValue($key)  //Returns user supplied and/derrived values.
    {
        return $this->values[$key];
    }
    
    public function getError($key)  //Returns and error for a specific field.
    {
        return $this->errors[$key];
    }
    
   
    
    /* Public Methods */
    
    /**
     * A method that supplies a Cross-Site Request Forgery token to the client
     * code. Typically, this token is stored in a hidden field in HTML.
     */
    public function getFormToken()
    {
        return $this->formToken;
    }

    /**
     * "An optional, empty field is good!"
     * 
     * A method that provides CSS overrides for optional inputs
     * when they are left empty by the user, but some other field
     * fails, causing the form to redraw. 
     * 
     * For isntance, if the word "Optional" appears next to an empty field after
     * a failed form submission, it will not be shown in red. Typically, the override
     * color is green. After all, "an empty optional field is good!"
     */
    public function setOptionalMessageColor()
    {                
        foreach($this->optionalInputs as $value)
        {   
            $result = $this->classes[$value];
            
            $this->classes[$value . 'ErrorMessage'] = ($result === '1' || $result === 'goodNodes') ? 'optionalMessageColor' : '';
        }
    }
}


/**
 * This class is like a "page manager."
 * 
 * A class for interfacing with the HTML. This class holds all data and methods
 * and data for making the user interface work
 * 
 * Most of all, this class uses other obejcts (aggregation) to get work done.
 */
class DomainPage extends Webpage
{
    /* Properties */
    const FORM_TOKEN_EXPIRE_MINUTES = 120;  //Cross Site Request Forgery deterrent.
    
    private $domains = NULL;
    
    //Arrays
    protected $values  = [
                          'statusMsg'    => '',
                          'compositeStr' => '',
                          'report'       => '',
                          'tableBody'    => ''
                        ];
    
    //Deals with CSS stuff
    protected $optionalInputs = NULL;      //Where optional means inputs may be the empty string ('').
    
    protected $classes = ['compositeStr' => '', 'statusMsgPara' => '', 'outputDiv' => ''];
    protected $errors  = ['compositeStr' => ''];
    
    //Objects
    protected $validator = NULL; //Provides data for the Webpage class, and/or sub-classes.
    
    /*Constructor*/
    public function __construct(Escaper $escaper, HTML $html, Cipher $cipher)
    {           
        parent::__construct($escaper, $html, $cipher);
    }

    /* Mutators */
    public function setValidator(Validator $validator)
    {
        if(!($validator instanceof DomainPageValidatorPOST))
        {
            throw new InvalidArgumentException("The wrong kind of Validator was supplied. Needs a DomainPageValidatorPOST.");
        }
        
        $this->validator = $validator;
        return;
    }

    /**
     * A method for generating a report.
     */
    private function makeReport($flag = false)
    {
        $report = '';
        
        if($flag === true)
        {
            $numDomains = count($this->domains);
            
            if($numDomains === 1)
            {
                $report = 'There is only ' .$numDomains. ' domain.';
            }
            else
            {
                $report = 'There are ' .$numDomains. ' unique domains.';
            }
        }
        
        return $report;
    }
    
    /**
     * A method that displays processing results in a table format.
     */
    private function fillTableBody($flag = false)
    {
        if($flag === true)
        {
            return $this->values['tableBody'];
        }

        return ''; //There are no results to dispaly.
    }
    
    /**
     * A method that shows successfully processed data.
     */
    private function showResults()
    {
        /* DISPLAY the following data as processing results. */
        
        //Get the processed data.
        $this->domains = $this->validator->getTranslatedInputArray();
        $this->escaper->htmlEntitiesArray($this->domains);
      
        //Set the status message.
        $this->values['statusMsg'] = 'Success! Processing complete!';
        
        //Set the CSS class for the status message.
        $this->classes['statusMsgPara'] = 'goodNodeText';
        $this->classes['outputDiv'] = 'visible';
        
        //Format processed data for display.
        $this->values['tableBody'] = $this->html->drawTableBody($this->domains);
        
        //Generate report.
        $this->values['report'] = $this->makeReport(true);
        
        return;
    }
    
    
    /**
     * A method that dispalys error messages when processing fails.
     */
    private function showErrors()
    {
        /*REDRAW The Email Domain Lister form with the following data.!!!*/

        //For sticky form data.
        $this->values = $this->validator->getFilteredInputArray();
        $this->escaper->htmlEntitiesArray($this->values);

        //For CSS visual error indication.
        $this->classes = $this->validator->getClasses();
        $this->classes['statusMsgPara'] = '';
        $this->escaper->htmlEntitiesArray($this->classes);
        
        //For error messages.
        $this->errors = $this->validator->getErrorMessagesArray();
        $this->escaper->htmlEntitiesArray($this->errors);
        
        $this->values['statusMsg'] = implode('<br>', $this->errors); //HTML5 <br>
        
        //Format processed data for display.
        $this->values['tableBody'] = $this->fillTableBody(false);
        
        //Generate report.
        $this->values['report'] = $this->makeReport(false);
        return;
    }
    
    /**
     * A method that wraps the vaildation test and takes action
     * based on the results.
     */
    public function useHttpPostInputs()
    {
        if($this->validator->validate()) //Where the form inputs are tested.
        {   
            $this->showResults();
        }
        else
        {
            $this->showErrors();
        }

        return;
    }
}


/*******************************************************************************
 *                                                                             *
 *                      Now, let us run something. Sheeh!                      *
 *                                                                             *
 *******************************************************************************/
try
{
    //Instantiate maintenance classes
    $errorHandler = new ErrorHanlder();
    $session      = new Session();
    $utility      = new Utility();
    

    //For santiizing critial $_SERVER / INPUT_SERVER values.
    $serverSanitizer = new ServerSanitizer();
    $serverCleaner   = new ServerCleaner($serverSanitizer);
    $serverCleaner->clean();
    
    //For validating critial $_SERVER / INPUT_SERVER values.
    $serverValidator = new ServerValidator($serverCleaner->getCleanData());
    $serverValidator->validate();          //Any error throws an exception and is fatal.
    
    //For getting work done on the page itself.
    $escaper = new Escaper(); //XSS defense
    $html    = new HTML();    //Draws various screen elements.
    $cipher  = new Cipher();  //CSRF token generator.
    $webpage = new DomainPage($escaper, $html, $cipher);  //An object for this page, that represents the page.
    

    if($serverValidator->isPOST($serverSanitizer)) //It needs the $serverSanitizer to filter the HTTP_REFERER element in INPUT_SERVER before validating it.
    {      
        //Free up resources.
        $serverCleaner   = NULL;
        $serverSanitizer = NULL;
        $serverValidator = NULL;  
        unset($serverCleaner, $serverSanitizer, $serverValidator);
        
        //For sanitizing form inputs.
        $postSanitizer = new PostSanitizer();
        $cleaner       = new DomainPageCleanerPOST($postSanitizer);  //A Cleaner uses Sanitizer. :-)
        $cleaner->clean();

        //For validating e-mail addresses.
        $string         = new String('UTF-8');
        $emailValidator = new EmailValidator($string);
        
        //For validating form inputs **AND** e-mail addresses found in the compositeStr <textarea>
        $postValidator = new DomainPageValidatorPOST($emailValidator, $string, $cleaner->getCleanData());
        
        $webpage->setValidator($postValidator);  //The DomainPageValidatorPOST object will provide information for the DomainPage object to display.
        $webpage->useHttpPostInputs();           //The alternative is to use the default, pre-establishe, GET values for screen elements inside of class DomainPage
    }
    elseif($serverValidator->isGET())    //Checks the request identity (IP & User Agent), token timeout, and more.
    {        
        //Free up resources.
        $serverCleaner   = NULL;
        $serverSanitizer = NULL;
        $serverValidator = NULL;  
        unset($serverCleaner, $serverSanitizer, $serverValidator);
        
        //Use class properties of DomainPage for screen elements.
    }
    else
    {
        $errorMessages = $serverValidator->getErrorMessagesArray();
        
        //Free up resources.
        $serverCleaner   = NULL;
        $serverSanitizer = NULL;
        $serverValidator = NULL;  
        $webpage         = NULL;
        $escaper         = NULL;
        $html            = NULL;
        $cipher          = NULL;
        $session         = NULL;
        $errorHandler    = NULL;
        $utility         = NULL;
        unset($serverCleaner, $serverSanitizer, $serverValidator, $webpage, $escaper, $html, $cipher, $session, $errorHandler, $utility);
        throw new SecurityException("Unauthorized HTTP request for index.php.\n" . print_r($errorMessages, true));
    }
    
    $webpage->setFormToken();  //Sets the CSRF token and stores a copy in $_SESSION.
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
    <head>
        <meta charset="utf-8">
        <meta name="author" content="Anthony E. Rutledge">
        <meta name="copyright" content="&copy; 2016 Anthony E. Rutledge">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <style type="text/css">
            /* CSS reset */
            html, body, div, span, applet, object, iframe, h1, h2, h3, h4, h5, h6, p, blockquote, pre, a, abbr, acronym, address, big, cite, code, del, dfn, em, img, ins, kbd, q, s, samp, small, strike, strong, sub, sup, tt, var, b, u, i, center, dl, dt, dd, ol, ul, li, fieldset, form, label, legend, table, caption, tbody, tfoot, thead, tr, th, td, article, aside, canvas, details, embed, figure, figcaption, footer, header, hgroup, menu, nav, output, ruby, section, summary, time, mark, audio, video {
                border: 0 none;
                font: inherit;
                margin: 0;
                padding: 0;
                vertical-align: baseline;
            }
            html
            {
                height: 100%;
            }
            body 
            {
                background-attachment: fixed;
                background-color: #a4a4a4;
                background-image: radial-gradient(white, grey, black);
                background-repeat: no-repeat;
                font-family: arial,sans-serif;
                line-height: 1em;
                overflow: auto;
                text-align: center;
            }
            div, nav, section, article, aside, footer
            {
                padding: 5px;
                background-color: white;
                border-radius: 4px;
                box-shadow: 0 0 15px #888888;
            }
            h1
            {
                font-size: 2em;
                font-weight: bold;
                margin: 10px 0;
            }
            h2 
            {
                font-size: 1.5em;
                font-weight: bold;
                margin: 10px 0;
            }
            /* Element Selectors */
            label
            {
                font-weight: bold;
            }
            table
            {
                border: 2px solid black;
            }
            thead
            {
                text-align: center;
                font-weight: bold;
            }
            th:first-child
            {
                border-right: 1px solid black;
            }
            th
            {
                border-bottom: 2px solid black;
            }
            tfoot
            {
                text-align: center;
            }
            td
            {
                padding: 2px;
                border-bottom: 1px solid black;
                text-align: center;
            }
            button:hover
            {
                cursor: pointer;
                box-shadow: 0 0 7px yellow;
            }
            
            /* ID Selectors */
            #wrapper
            {
                width: 700px;
                margin: 50px auto;
                text-align: center;
            }
            #titleDiv
            {
                height: 300px;
            }
            #instructionsPara
            {
                margin: 20px 0 60px 0;
                color: blue;
                font-weight: bold;
            }
            #formDiv
            {
                display: inline-block;
                margin: 0 auto;
            }
            #compositeStrLabel
            {
                width: 140px;
                margin: 0 0 5px 0;
                padding: 1px;
                text-align: left;
                float: left;
            }
            #compositeStrTextarea
            {
                margin: 0 auto 10px;
                width: 675px;
                height: 200px;
                border: 1px solid black;
            }
            #compositeStrTextarea:hover, #compositeStrTextarea:focus
            {
                border: 1px solid blue;
                box-shadow: 0 0 2.5px blue;
            }
            #compositeStrTextarea:focus
            {
                background-color: blanchedalmond;
            }
            #statusMsgPara
            {
                height: 20px;
                margin: 0 auto 10px;
                color:red;
            }
            #listBtn
            {
                width: 175px;
                height: 60px;
                font-size: 14px;
                font-weight: bold;
            }
            #outputDiv
            {
                margin: 50px auto;
                visibility: hidden;
            }
            #emailDomainTable
            {
                width: 250px;
                margin: 0 auto;
                border: 2px solid black;
                font-size: 16px;
                text-align: left;
            }
            #emailDomainTable tbody tr > td:first-child
            {
                border-right: 1px solid black;
            }
            #emailDomainTable tbody tr:odd > td
            {
                background-color: tan;
            }
            #emailDomainTable tbody tr:even > td
            {
                background-color: antiquewhite;
            }
            #emailDomainTable tbody tr > td:last-child
            {
                font-style: italic;
            }
            #tableFooter
            {
                border: none;
            }
            #wrapper, #formDiv /* Un-styles specific divs */
            {    
                border: none;
                background: none;
                border-radius: 0;
                box-shadow: none;
            }
            /* UI Effects */
            .visible
            {
                visibility: visible !important;
            }
            /* Error Indication */
            .goodNodeText
            {
                color: green !important;
            }
            .badNodes
            {
                background-color: pink;
                border: 1px solid red !important;
                box-shadow: 0 0 2.5px red;
            }
        </style>
        <title>ASCI E-mail Domain Lister</title>
    </head>
    <body>
        <div id="wrapper">
            <div id="inputDiv">
                <h1 id="title">Secure E-mail Domain Lister! ;-)</h1>
                <p id="instructionsPara">Please enter e-mail addresses separated by *whitespace*.</p>
                <div id="formDiv">
                    <form id="emailDomainForm" name="emailDomainForm" class="" enctype="application/x-www-form-urlencoded" accept-charset="UTF-8" autocomplete="on" method="post" action="index.php">
                        <label id="compositeStrLabel" for="compositeStrTextarea">E-Mail Addresses</label>
                        <textarea id="compositeStrTextarea" name="compositeStr" class="<?= $webpage->getClass('compositeStr'); ?>" tabindex="1" title="Enter e-mail addresses separated by whitespace." spellcheck="false" minlength="6" placeholder="you@yahoo.com her@gmail.com him@umich.edu ..." required="required"><?= $webpage->getValue('compositeStr'); ?></textarea>
                        <p id="statusMsgPara" class="<?= $webpage->getClass('statusMsgPara'); ?>"><?= $webpage->getValue('statusMsg'); ?></p>
                        <button id="listBtn" name="listBtn" type="submit" tabindex="2" title="Click to create a domain list." value="List">List Unique Domains</button>
                        <input type="hidden" name="token" value="<?= $webpage->getFormToken(); ?>">
                    </form>
                </div>
            </div>
            <div id="outputDiv" class="<?= $webpage->getClass('outputDiv'); ?>">
                <table id="emailDomainTable" class="" dir="ltr" lang="en-US" title="A table of unique and resolved domain names." summary="This table is an ordered list of domain names from the email addresses submitted above.">
                    <caption>
                        <h2>Domain Names</h2>
                    </caption>
                    <colgroup>
                        <col width="10%">
                        <col width="90%">
                    </colgroup>
                    <thead>
                        <tr>
                            <th>Number</th>
                            <th>Domain</th>
                        </tr>
                    </thead>
                    <tfoot><!--Yes, this is the correct order.-->
                        <tr>
                            <td id="tableFooter" colspan="2"><?= $webpage->getValue('report'); ?></td>
                        </tr>
                    </tfoot>
                    <tbody>
                        <?= $webpage->getValue('tableBody'); ?>
                    </tbody>
                </table>
            </div>
        </div>
    </body>
</html>
<?php
}
catch(SanitizationException $sane)
{
    //error_log($sane->getMessage() ."\n". $sane->getTraceAsString());
    $session->kill();
    $utility->redirect('fbi');
}
catch(ValidationException $vale)
{
    //error_log($vale->getMessage() ."\n". $vale->getTraceAsString());
    $session->kill();
    $utility->redirect('fbi');
}
catch(SecurityException $sece)
{
    //error_log($sece->getMessage() ."\n". $sece->getTraceAsString());
    $session->kill();
    $utility->redirect('fbi');
}
catch(RuntimeException $re)
{
    //error_log($re->getMessage() ."\n". $re->getTraceAsString());
    $session->kill();
    $utility->redirect('fbi');
}
catch(LogicException $le)
{
    //error_log($le->getMessage() ."\n". $le->getTraceAsString());
    $session->kill();
    $utility->redirect('fbi');
}
catch(ErrorException $ee)
{
    //error_log($ee->getMessage() ."\n". $ee->getTraceAsString());
    $session->kill();
    $utility->redirect('fbi');
}
catch(Exception $ex)
{
    //error_log($ex->getMessage() ."\n". $ex->getTraceAsString());
    $session->kill();
    $utility->redirect('fbi');
}
finally
{   
    $webpage = NULL;
    $escaper = NULL;
    $html    = NULL;
    $cipher  = NULL;
    $utility = NULL;
    $errorHandler = NULL;
    $session = NULL;
    unset($webpage, $escaper, $html, $cipher, $utility, $errorHandler, $session);
}
?>
