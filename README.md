# weggli-patterns
Collections of patterns for weggli to find nice bugs


## find strcpy-like/memcpy calls with static arrays

```
weggli -R 'func=^str.*cpy$' '{char $b[_]; $func($b, _);}' source

    static char buf[256];

    if ( var1 && obj->a )
    {
        d = obj->a(obj->h);
        if ( e < 300 )
..
      strcpy(someotherbuf,pValue);
    }
    else if(!strcmp("somestring",pParams[i].Name))
    {
      if(pValue != NULL)
      strcpy(buf,pValue);
```



## find strcpy/memcpy calls with length of source input instead of length of destination buffer

```
weggli --unique -R 'func=.*cpy$' '{$func($_, _($a), _($a));}' src                                                                                                                                                                                                                                                  
test.c:371
void some_function(char* conn)
{
..

    strncpy(ps->var[0].value, conn, strlen(conn));
..
    return;
}
```

```
weggli -R 'func=.*cpy$' '{$func($_, $a._, $a._);}' src                                                                                                                                                                                                                                                                                                   
test.c:897
static int stuff(
..
        memcpy(buf, header->value.buf, header->value.length);
..
}
```

## strncpy-like with potential arithmetic errors

```
weggli --unique -R 'func=.*ncpy$' '{$func($_, _($a), $n - $m);}' source

size_t m = strlen(test->user_data);
size_t n = m + (s - test->c) - 5;
strncpy(test->a, test->b, n - m); // n and m are unsigned, if m > n, buffer overflow

```



## malloc-like calls with potential integer overflows

```
weggli -R '$fn=lloc' '{$size; $size=_+_; $fn($size);}' source
weggli -R '$fn=lloc' '{$user_num=atoi(_);$fn($user_num);}' source
```

## unitialized pointers

```
weggli '{ _* $p;NOT: $p = _;$func(&$p);}' source
 
char *name;
int id = a(val[i].parameterName, &name);
 ```
 
 ## format string functions calls' return values to index buffers
 
 ```
weggli -R '$fn=printf$' '{$ret = $fn$($b,_,_);$b[$ret] = _;}' source
 ```
 
 ## no space for zero terminator
 
 `weggli '{$len=strlen($buf);$dest=malloc($len);strcpy($dest,$buf);}' source`
 
 ```
 weggli '{$dest=malloc(strlen($buf));strcpy($dest,$buf);}' test.c                                                                              14:29:41
char *copy;
copy = (char *)malloc(strlen(input));
strcpy(copy, input);
return copy;
```


## format string bugs

`weggli -R '$fn=printf$' -R '$arg=[^"]*' '{$fn($arg);}' test2.c`

This query doesn't work well for format string functions with length specifiers such as snprintf. Here is another one (also not perfect):

```
weggli -R '$fn=^[^n]*printf$' -R '$arg=[^"]*' '{$fn($arg);}' src #for fprintf, printf, etc

weggli -R '$fn=nprintf$' -R '$arg=[^"]*' '{$fn($_,$_,$arg);}' src # for snprintf, etc
```


## integer overflows

```
weggli '{$user_num=atoi(_);$user_num+_;}' source


i = atoi(instanceNumber);
if(i <= 0 || i > objN) return -1;
return i + b;
```

## typical buffer overruns in loops

### Find CVE 2017-9765

```
weggli ' {                                                                                                                                               
    _ $buf[_]; $t = $buf;while (_) { $t; }
}' toto.c


toto.c:1395
static soap_wchar
soap_get_pi(struct soap *soap)
{ char buf[64];
  register char *s = buf;
  register int i = sizeof(buf);
  register soap_wchar c = soap_getchar(soap);
  /* This is a quick way to parse XML PI and we could use a callback instead to
   * enable applications to intercept processing instructions */
  while ((int)c != EOF && c != '?')
  { if (--i > 0)
    { if (soap_blank(c))
        c = ' ';
      *s++ = (char)c;
    }
    c = soap_getchar(soap);
  }
  *s = '\0';
  DBGLOG(TEST, SOAP_MESSAGE(fdebug, "XML PI <?%s?>\n", buf));
..
}
```

## TOCTOU

Needs more function names but you get the idea

```
weggli -R '$f1=(fopen|chmod|access|stat)' -R '$f2=(fopen|chmod|access|stat)' '{$f1($name);$f2($name);}' test3.c                               15:02:42
int main(void) {
char *file_name;
FILE *f_ptr;

/* Initialize file_name */

f_ptr = fopen(file_name, "w");
if (f_ptr == NULL)  {
  /* Handle error */
}

/* ... */

if (chmod(file_name, S_IRUSR) == -1) {
  /* Handle error */
}
}
```



## double free

```
weggli -R '$fn=free' '{$fn($a);not: $a=_;not: return _;$fn($a);}' doublefree.c

int bad_code1() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    free(var); // <-bug
    return 0;
}
```


## use after free

```
weggli -R '$fn=free' '{$fn($a);not: $a=_;not: return _;_($a);}' use-after-free.c                             


use-after-free.c:8
int bad_code1() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var->func("use after free");
    return 0;
}
```

## find buffers passed as function arguments and freed within the function body

```
weggli '_ $fn(_ $buf) {                                                                                        
    free($buf);
}' source
test.c:930
int parse_stuff(char* Ctx)
{

    test(Ctx, 0, 0, 1);
..
#endif
    }

    //Free allocated memory
    free(Ctx->bufferCtx.pBuf);
    free(Ctx); // <-- 

    return -1;
}
```

Each finding must be analyzed to check if the freed buffer is used by the caller or freed one more time by mistake.



# 0xdea semgrep's rules

## buffer overflows

[**insecure-api-gets**](https://github.com/0xdea/semgrep-rules/blob/main/c/insecure-api-gets.yaml). Use of the insecure API function gets().

```c
weggli '{gets(_);}' test_cases/insecure-api-gets.c 
/test_cases/insecure-api-gets.c:7
void get_string()
{
	char buf[BUFSIZE];

	// ruleid: raptor-insecure-api-gets
	gets(buf);
}
```


[**insecure-api-strcpy-stpcpy-strcat**](https://github.com/0xdea/semgrep-rules/blob/main/c/insecure-api-strcpy-stpcpy-strcat.yaml). Use of potentially insecure API functions strcpy(), stpcpy(), strcat().

```c
weggli -R '$fn=(strcpy|stpcpy|strcat|wcscpy|wcpcpy|wcscat)' '{$fn(_);}' test_cases/insecure-api-strcpy-stpcpy-strcat.c
test_cases/insecure-api-strcpy-stpcpy-strcat.c:74
int process_email(char *email)
{
..
	// ruleid: raptor-insecure-api-strcpy-stpcpy-strcat
	strcpy(domain, delim);

	if (!strchr(delim, '.'))
		// ruleid: raptor-insecure-api-strcpy-stpcpy-strcat
		strcat(domain, default_domain);

	// ...
}
test_cases/insecure-api-strcpy-stpcpy-strcat.c:105
void process_address(int sockfd)
{
..

	if (ptr)
       		*ptr++ = '\0';

	// ruleid: raptor-insecure-api-strcpy-stpcpy-strcat
   	strcpy(username, netbuf);

	if (ptr)
		// ruleid: raptor-insecure-api-strcpy-stpcpy-strcat
		strcpy(domain, ptr);

..
}
```


[**insecure-api-sprintf-vsprintf**](https://github.com/0xdea/semgrep-rules/blob/main/c/insecure-api-sprintf-vsprintf.yaml). Use of potentially insecure API functions sprintf() and vsprintf().
     
This one is harder to make using weggli because of FMT regex.


[**insecure-api-scanf-etc**](https://github.com/0xdea/semgrep-rules/blob/main/c/insecure-api-scanf-etc.yaml). Use of potentially insecure API functions in the scanf() family.

Same

[**incorrect-use-of-strncat**](https://github.com/0xdea/semgrep-rules/blob/main/c/incorrect-use-of-strncat.yaml). Wrong size argument passed to strncat().

Unfortunately, it's not possible to match buffer length with weggli: https://github.com/weggli-rs/weggli/issues/59


So, this one won't work: `weggli -v '{_ $dst[$len];strncat($dst, _, $len);}' test_cases/incorrect-use-of-strncat.c`


If you run this one `weggli -v '{_ $dst[_];strncat($dst, _, _);}' test_cases/incorrect-use-of-strncat.c` instead, you can match them with many false positive.

For the other queries of the pattern [here](https://github.com/0xdea/semgrep-rules/blob/main/c/incorrect-use-of-strncat.yaml), this query works:

```c
weggli -u '{_ $dst[_];strncat($dst, _, _(strlen(_)));}' -p '{_ $dst[_];strncat($dst, _, sizeof(_));}' test_cases/incorrect-use-of-strncat.c
test_cases/incorrect-use-of-strncat.c:32
int copy_data3(char *username)
{
	char buf[1024];

	strcpy(buf, "username is: ");
	// ruleid: raptor-incorrect-use-of-strncat
	strncat(buf, username, sizeof(buf) - strlen(buf));

	log("%s\n", buf);

	return 0;
}
test_cases/incorrect-use-of-strncat.c:45
int good(char *username)
{
	char buf[1024];

	strcpy(buf, "username is: ");
	// ok: raptor-incorrect-use-of-strncat
	strncat(buf, username, sizeof(buf) - strlen(buf) - 1);

	log("%s\n", buf);

	return 0;
}
test_cases/incorrect-use-of-strncat.c:6
int copy_data(char *username)
{
	char buf[1024];

	strcpy(buf, "username is: ");
	// ruleid: raptor-incorrect-use-of-strncat
	strncat(buf, username, sizeof(buf));

	log("%s\n", buf);

	return 0;
}
```



* [**incorrect-use-of-strncpy-stpncpy-strlcpy**](https://github.com/0xdea/semgrep-rules/blob/main/c/incorrect-use-of-strncpy-stpncpy-strlcpy.yaml). Wrong size argument passed to strncpy(), stpncpy(), strlcpy().

Same remark as above.

```c
weggli -R '$fn=(strncpy|stpncpy|strlcpy)' '{$fn($dst, $src, _($src));}' test_cases/incorrect-use-of-strncpy-stpncpy-strlcpy.c              15:03:23
test_cases/incorrect-use-of-strncpy-stpncpy-strlcpy.c:3
void test_func()
{
	char source[21] = "the character string";
	char dest[12];

	// ruleid: raptor-incorrect-use-of-strncpy-stpncpy-strlcpy
	strncpy(dest, source, sizeof(source)-1);
}
test_cases/incorrect-use-of-strncpy-stpncpy-strlcpy.c:120
int
main(int argc, char *argv[])
..
		up->p_state = (info.pr_nlwp == 0? ZOMBIE : RUNNING);
		up->p_time = 0;
		up->p_ctime = 0;
		up->p_igintr = 0;
		// ruleid: raptor-incorrect-use-of-strncpy-stpncpy-strlcpy
		(void) strncpy(up->p_comm, info.pr_fname,
		    sizeof (info.pr_fname));
		up->p_args[0] = 0;

		if (up->p_state != NONE && up->p_state != ZOMBIE) {
			(void) strcpy(fname, "status");

..
}
```

* [**incorrect-use-of-sizeof**](https://github.com/0xdea/semgrep-rules/blob/main/c/incorrect-use-of-sizeof.yaml). Accidental use of the sizeof() operator on a pointer instead of its target.

```c
weggli -R '$fn=alloc$' '{$ptr = $fn(_); sizeof($ptr);}' -p '{_ *$p;sizeof($p);}' test_cases/incorrect-use-of-sizeof.c                      15:20:49
test_cases/incorrect-use-of-sizeof.c:8
void bad1()
{
	double *foo;

	// ruleid: raptor-incorrect-use-of-sizeof
	foo = (double *)malloc(sizeof(foo));
}
test_cases/incorrect-use-of-sizeof.c:41
void bad3()
{
	AnObj *o = (AnObj *) malloc(sizeof(AnObj));
	// ruleid: raptor-incorrect-use-of-sizeof
	memset(o, 0x0, sizeof(o));
}
test_cases/incorrect-use-of-sizeof.c:48
char *read_username(int sockfd)
{
	char *buffer, *style, userstring[1024];
	int i;

	buffer = (char *)malloc(1024);

	if (!buffer) {
		error("buffer allocation failed: %m");
		return NULL;
	}
..
		*style++ = '\0';
	sprintf(buffer, "username=%.32s", userstring);

	if (style)
	// ruleid: raptor-incorrect-use-of-sizeof
		snprintf(buffer, sizeof(buffer) - strlen(buffer) - 1, ", style=%s\n", style);

	return buffer;
}
test_cases/incorrect-use-of-sizeof.c:8
void bad1()
{
	double *foo;

	// ruleid: raptor-incorrect-use-of-sizeof
	foo = (double *)malloc(sizeof(foo));
}
test_cases/incorrect-use-of-sizeof.c:48
char *read_username(int sockfd)
{
	char *buffer, *style, userstring[1024];
	int i;

	buffer = (char *)malloc(1024);

	if (!buffer) {
..
		*style++ = '\0';
	sprintf(buffer, "username=%.32s", userstring);

	if (style)
	// ruleid: raptor-incorrect-use-of-sizeof
		snprintf(buffer, sizeof(buffer) - strlen(buffer) - 1, ", style=%s\n", style);

	return buffer;
}
```

[**unterminated-string-strncpy-stpncpy**](https://github.com/0xdea/semgrep-rules/blob/main/c/unterminated-string-strncpy-stpncpy.yaml). Lack of explicit null-termination after strncpy() and stpncpy().

```c
weggli -R '$fn=(strncpy|stpncpy|strlcpy|strncpy|wcpncpy|wcsncpy)' '{$fn($dst, $src, _);not: $dst[_] = _;}' test_cases/unterminated-string-strncpy-stpncpy.c
test_cases/unterminated-string-strncpy-stpncpy.c:8
void copy_string1(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-unterminated-string-strncpy-stpncpy
	strncpy(buf, string, BUFSIZE);
}
test_cases/unterminated-string-strncpy-stpncpy.c:16
void copy_string2(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-unterminated-string-strncpy-stpncpy
	stpncpy(buf, string, BUFSIZE);
}
test_cases/unterminated-string-strncpy-stpncpy.c:24
int test_func()
{
	char longString[] = "String signifying nothing";
	char shortString[16];

	// ruleid: raptor-unterminated-string-strncpy-stpncpy
	strncpy(shortString, longString, 16);
	printf("The last character in shortString is: %c (%1$x)\n", shortString[15]);
	return 0;
}
test_cases/unterminated-string-strncpy-stpncpy.c:51
void authenticate(int sockfd)
{
..
	read_string(buffer, size);

	switch(cmd) {
	case USERNAME:
		// ruleid: raptor-unterminated-string-strncpy-stpncpy
		strncpy(user, buffer, sizeof(user));
		if (!is_username_valid(user))
			goto fail;
		break;
	// ...
	}
..
}
test_cases/unterminated-string-strncpy-stpncpy.c:79
int process_email(char *email)
{
	char buf[1024], *domain;

	// ruleid: raptor-unterminated-string-strncpy-stpncpy
	strncpy(buf, email, sizeof(buf));

	domain = strchr(buf, '@');
	if(!domain)
		return -1;

..
}
```


* [**off-by-one**](https://github.com/0xdea/semgrep-rules/blob/main/c/off-by-one.yaml). Potential off-by-one error.
* [**pointer-subtraction**](https://github.com/0xdea/semgrep-rules/blob/main/c/pointer-subtraction.yaml). Potential use of pointer subtraction to determine size.
* [**unsafe-ret-snprintf-vsnprintf**](https://github.com/0xdea/semgrep-rules/blob/main/c/unsafe-ret-snprintf-vsnprintf.yaml). Potentially unsafe use of the return value of snprintf() and vsnprintf().
* [**unsafe-ret-strlcpy-strlcat**](https://github.com/0xdea/semgrep-rules/blob/main/c/unsafe-ret-strlcpy-strlcat.yaml). Potentially unsafe use of the return value of strlcpy() and strlcat().
* [**write-into-stack-buffer**](https://github.com/0xdea/semgrep-rules/blob/main/c/write-into-stack-buffer.yaml). Direct writes into buffers allocated on the stack.

## miscellaneous


[**argv-envp-access**](https://github.com/0xdea/semgrep-rules/blob/main/c/argv-envp-access.yaml). Command-line argument or environment variable access.

`weggli -R '$arg=(argv|envp)' '{$arg;}' test_cases/argv-envp-access.c`

```c
test_cases/argv-envp-access.c:6
int main(int argc, char** argv)
{
	char cmd[CMD_MAX] = "/usr/bin/cat ";
	// ruleid: raptor-argv-envp-access
	strcat(cmd, argv[1]);
	system(cmd);

	return 0;
}
```



# Original examples

Examples by felixwilhelm

Calls to memcpy that write into a stack-buffer:

```c
weggli '{
    _ $buf[_];
    memcpy($buf,_,_);
}' ./target/src
```

Calls to foo that don't check the return value:
```c
weggli '{
   strict: foo(_);
}' ./target/src
```

Potentially vulnerable snprintf() users:
```c
weggli '{
    $ret = snprintf($b,_,_);
    $b[$ret] = _;
}' ./target/src
```

Potentially uninitialized pointers:
```c
weggli '{ _* $p;
NOT: $p = _;
$func(&$p);
}' ./target/src
```

Potentially insecure WeakPtr usage:
```cpp
weggli --cpp '{
$x = _.GetWeakPtr(); 
DCHECK($x); 
$x->_;}' ./target/src
```

Debug only iterator validation:
```cpp
weggli -X 'DCHECK(_!=_.end());' ./target/src
```

Functions that perform writes into a stack-buffer based on
a function argument. 
```c
weggli '_ $fn(_ $limit) {
    _ $buf[_];
    for (_; $i<$limit; _) {
        $buf[$i]=_;
    }
}' ./target/src
```

Functions with the string decode in their name
```c
weggli -R func=decode '_ $func(_) {_;}'
```

Encoding/Conversion functions
```c
weggli '_ $func($t *$input, $t2 *$output) {
    for (_($i);_;_) {
        $input[$i]=_($output);
    }
}' ./target/src
```

