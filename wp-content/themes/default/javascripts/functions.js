
function setCookie() {
if(arguments.length < 2) { return; }
var n = arguments[0];
var v = arguments[1];
var d = 0;
if(arguments.length > 2) { d = parseInt(arguments[2]); }
var exp = '';
if(d > 0) {
	var now = new Date();
	then = now.getTime() + (d * 24 * 60 * 60 * 1000);
	now.setTime(then);
	exp = '; expires=' + now.toGMTString();
	}
document.cookie = n + "=" + escape(String(v)) + '; path=/' + exp;
} // function SetCookie()

function readCookie(n) {
var cookiecontent = new String();
if(document.cookie.length > 0) {
	var cookiename = n+ '=';
	var cookiebegin = document.cookie.indexOf(cookiename);
	var cookieend = 0;
	if(cookiebegin > -1) {
		cookiebegin += cookiename.length;
		cookieend = document.cookie.indexOf(";",cookiebegin);
		if(cookieend < cookiebegin) { cookieend = document.cookie.length; }
		cookiecontent = document.cookie.substring(cookiebegin,cookieend);
		}
	}
return unescape(cookiecontent);
} // function ReadCookie()

function isFirstTimeVisit() {
    return readCookie("is_mafiosi") != "yes";
}

function showFirstTimeScreen() {
    if(isFirstTimeVisit()) {
        setCookie('is_mafiosi', 'yes', 365);
        jQuery.facebox(function() {
          jQuery.get('/welcome_message.html', function(data) {
            jQuery.facebox('<div style="width: 800px; height: 400px; overflow: auto">' + data + "</div>")
          });
}) 
    }
}
