#ASCI_OPP_PHP_Code_Sample
#
# ***********************************************************
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
       Input: Strings (e-mail addresses and other) and white space (\r,\n,\t, spaces, etc...).
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
