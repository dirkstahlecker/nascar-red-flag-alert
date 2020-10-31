// load SHA
//if(typeof jsSHA === 'undefined'){
/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-4 and FIPS PUB 202, as well as the corresponding
 HMAC implementation as defined in FIPS PUB 198a

 Copyright Brian Turek 2008-2017
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information

 Several functions taken from Paul Johnston
*/
'use strict';(function(Y){function C(c,a,b){var e=0,h=[],n=0,g,l,d,f,m,q,u,r,I=!1,v=[],w=[],t,y=!1,z=!1,x=-1;b=b||{};g=b.encoding||"UTF8";t=b.numRounds||1;if(t!==parseInt(t,10)||1>t)throw Error("numRounds must a integer >= 1");if("SHA-1"===c)m=512,q=K,u=Z,f=160,r=function(a){return a.slice()};else if(0===c.lastIndexOf("SHA-",0))if(q=function(a,b){return L(a,b,c)},u=function(a,b,h,e){var k,f;if("SHA-224"===c||"SHA-256"===c)k=(b+65>>>9<<4)+15,f=16;else if("SHA-384"===c||"SHA-512"===c)k=(b+129>>>10<<
    5)+31,f=32;else throw Error("Unexpected error in SHA-2 implementation");for(;a.length<=k;)a.push(0);a[b>>>5]|=128<<24-b%32;b=b+h;a[k]=b&4294967295;a[k-1]=b/4294967296|0;h=a.length;for(b=0;b<h;b+=f)e=L(a.slice(b,b+f),e,c);if("SHA-224"===c)a=[e[0],e[1],e[2],e[3],e[4],e[5],e[6]];else if("SHA-256"===c)a=e;else if("SHA-384"===c)a=[e[0].a,e[0].b,e[1].a,e[1].b,e[2].a,e[2].b,e[3].a,e[3].b,e[4].a,e[4].b,e[5].a,e[5].b];else if("SHA-512"===c)a=[e[0].a,e[0].b,e[1].a,e[1].b,e[2].a,e[2].b,e[3].a,e[3].b,e[4].a,
    e[4].b,e[5].a,e[5].b,e[6].a,e[6].b,e[7].a,e[7].b];else throw Error("Unexpected error in SHA-2 implementation");return a},r=function(a){return a.slice()},"SHA-224"===c)m=512,f=224;else if("SHA-256"===c)m=512,f=256;else if("SHA-384"===c)m=1024,f=384;else if("SHA-512"===c)m=1024,f=512;else throw Error("Chosen SHA variant is not supported");else if(0===c.lastIndexOf("SHA3-",0)||0===c.lastIndexOf("SHAKE",0)){var F=6;q=D;r=function(a){var c=[],e;for(e=0;5>e;e+=1)c[e]=a[e].slice();return c};x=1;if("SHA3-224"===
    c)m=1152,f=224;else if("SHA3-256"===c)m=1088,f=256;else if("SHA3-384"===c)m=832,f=384;else if("SHA3-512"===c)m=576,f=512;else if("SHAKE128"===c)m=1344,f=-1,F=31,z=!0;else if("SHAKE256"===c)m=1088,f=-1,F=31,z=!0;else throw Error("Chosen SHA variant is not supported");u=function(a,c,e,b,h){e=m;var k=F,f,g=[],n=e>>>5,l=0,d=c>>>5;for(f=0;f<d&&c>=e;f+=n)b=D(a.slice(f,f+n),b),c-=e;a=a.slice(f);for(c%=e;a.length<n;)a.push(0);f=c>>>3;a[f>>2]^=k<<f%4*8;a[n-1]^=2147483648;for(b=D(a,b);32*g.length<h;){a=b[l%
    5][l/5|0];g.push(a.b);if(32*g.length>=h)break;g.push(a.a);l+=1;0===64*l%e&&D(null,b)}return g}}else throw Error("Chosen SHA variant is not supported");d=M(a,g,x);l=A(c);this.setHMACKey=function(a,b,h){var k;if(!0===I)throw Error("HMAC key already set");if(!0===y)throw Error("Cannot set HMAC key after calling update");if(!0===z)throw Error("SHAKE is not supported for HMAC");g=(h||{}).encoding||"UTF8";b=M(b,g,x)(a);a=b.binLen;b=b.value;k=m>>>3;h=k/4-1;if(k<a/8){for(b=u(b,a,0,A(c),f);b.length<=h;)b.push(0);
    b[h]&=4294967040}else if(k>a/8){for(;b.length<=h;)b.push(0);b[h]&=4294967040}for(a=0;a<=h;a+=1)v[a]=b[a]^909522486,w[a]=b[a]^1549556828;l=q(v,l);e=m;I=!0};this.update=function(a){var c,b,k,f=0,g=m>>>5;c=d(a,h,n);a=c.binLen;b=c.value;c=a>>>5;for(k=0;k<c;k+=g)f+m<=a&&(l=q(b.slice(k,k+g),l),f+=m);e+=f;h=b.slice(f>>>5);n=a%m;y=!0};this.getHash=function(a,b){var k,g,d,m;if(!0===I)throw Error("Cannot call getHash after setting HMAC key");d=N(b);if(!0===z){if(-1===d.shakeLen)throw Error("shakeLen must be specified in options");
    f=d.shakeLen}switch(a){case "HEX":k=function(a){return O(a,f,x,d)};break;case "B64":k=function(a){return P(a,f,x,d)};break;case "BYTES":k=function(a){return Q(a,f,x)};break;case "ARRAYBUFFER":try{g=new ArrayBuffer(0)}catch(p){throw Error("ARRAYBUFFER not supported by this environment");}k=function(a){return R(a,f,x)};break;default:throw Error("format must be HEX, B64, BYTES, or ARRAYBUFFER");}m=u(h.slice(),n,e,r(l),f);for(g=1;g<t;g+=1)!0===z&&0!==f%32&&(m[m.length-1]&=16777215>>>24-f%32),m=u(m,f,
    0,A(c),f);return k(m)};this.getHMAC=function(a,b){var k,g,d,p;if(!1===I)throw Error("Cannot call getHMAC without first setting HMAC key");d=N(b);switch(a){case "HEX":k=function(a){return O(a,f,x,d)};break;case "B64":k=function(a){return P(a,f,x,d)};break;case "BYTES":k=function(a){return Q(a,f,x)};break;case "ARRAYBUFFER":try{k=new ArrayBuffer(0)}catch(v){throw Error("ARRAYBUFFER not supported by this environment");}k=function(a){return R(a,f,x)};break;default:throw Error("outputFormat must be HEX, B64, BYTES, or ARRAYBUFFER");
    }g=u(h.slice(),n,e,r(l),f);p=q(w,A(c));p=u(g,f,m,p,f);return k(p)}}function b(c,a){this.a=c;this.b=a}function O(c,a,b,e){var h="";a/=8;var n,g,d;d=-1===b?3:0;for(n=0;n<a;n+=1)g=c[n>>>2]>>>8*(d+n%4*b),h+="0123456789abcdef".charAt(g>>>4&15)+"0123456789abcdef".charAt(g&15);return e.outputUpper?h.toUpperCase():h}function P(c,a,b,e){var h="",n=a/8,g,d,p,f;f=-1===b?3:0;for(g=0;g<n;g+=3)for(d=g+1<n?c[g+1>>>2]:0,p=g+2<n?c[g+2>>>2]:0,p=(c[g>>>2]>>>8*(f+g%4*b)&255)<<16|(d>>>8*(f+(g+1)%4*b)&255)<<8|p>>>8*(f+
    (g+2)%4*b)&255,d=0;4>d;d+=1)8*g+6*d<=a?h+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(p>>>6*(3-d)&63):h+=e.b64Pad;return h}function Q(c,a,b){var e="";a/=8;var h,d,g;g=-1===b?3:0;for(h=0;h<a;h+=1)d=c[h>>>2]>>>8*(g+h%4*b)&255,e+=String.fromCharCode(d);return e}function R(c,a,b){a/=8;var e,h=new ArrayBuffer(a),d,g;g=new Uint8Array(h);d=-1===b?3:0;for(e=0;e<a;e+=1)g[e]=c[e>>>2]>>>8*(d+e%4*b)&255;return h}function N(c){var a={outputUpper:!1,b64Pad:"=",shakeLen:-1};c=c||{};
    a.outputUpper=c.outputUpper||!1;!0===c.hasOwnProperty("b64Pad")&&(a.b64Pad=c.b64Pad);if(!0===c.hasOwnProperty("shakeLen")){if(0!==c.shakeLen%8)throw Error("shakeLen must be a multiple of 8");a.shakeLen=c.shakeLen}if("boolean"!==typeof a.outputUpper)throw Error("Invalid outputUpper formatting option");if("string"!==typeof a.b64Pad)throw Error("Invalid b64Pad formatting option");return a}function M(c,a,b){switch(a){case "UTF8":case "UTF16BE":case "UTF16LE":break;default:throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");
    }switch(c){case "HEX":c=function(a,c,d){var g=a.length,l,p,f,m,q,u;if(0!==g%2)throw Error("String of HEX type must be in byte increments");c=c||[0];d=d||0;q=d>>>3;u=-1===b?3:0;for(l=0;l<g;l+=2){p=parseInt(a.substr(l,2),16);if(isNaN(p))throw Error("String of HEX type contains invalid characters");m=(l>>>1)+q;for(f=m>>>2;c.length<=f;)c.push(0);c[f]|=p<<8*(u+m%4*b)}return{value:c,binLen:4*g+d}};break;case "TEXT":c=function(c,h,d){var g,l,p=0,f,m,q,u,r,t;h=h||[0];d=d||0;q=d>>>3;if("UTF8"===a)for(t=-1===
    b?3:0,f=0;f<c.length;f+=1)for(g=c.charCodeAt(f),l=[],128>g?l.push(g):2048>g?(l.push(192|g>>>6),l.push(128|g&63)):55296>g||57344<=g?l.push(224|g>>>12,128|g>>>6&63,128|g&63):(f+=1,g=65536+((g&1023)<<10|c.charCodeAt(f)&1023),l.push(240|g>>>18,128|g>>>12&63,128|g>>>6&63,128|g&63)),m=0;m<l.length;m+=1){r=p+q;for(u=r>>>2;h.length<=u;)h.push(0);h[u]|=l[m]<<8*(t+r%4*b);p+=1}else if("UTF16BE"===a||"UTF16LE"===a)for(t=-1===b?2:0,l="UTF16LE"===a&&1!==b||"UTF16LE"!==a&&1===b,f=0;f<c.length;f+=1){g=c.charCodeAt(f);
    !0===l&&(m=g&255,g=m<<8|g>>>8);r=p+q;for(u=r>>>2;h.length<=u;)h.push(0);h[u]|=g<<8*(t+r%4*b);p+=2}return{value:h,binLen:8*p+d}};break;case "B64":c=function(a,c,d){var g=0,l,p,f,m,q,u,r,t;if(-1===a.search(/^[a-zA-Z0-9=+\/]+$/))throw Error("Invalid character in base-64 string");p=a.indexOf("=");a=a.replace(/\=/g,"");if(-1!==p&&p<a.length)throw Error("Invalid '=' found in base-64 string");c=c||[0];d=d||0;u=d>>>3;t=-1===b?3:0;for(p=0;p<a.length;p+=4){q=a.substr(p,4);for(f=m=0;f<q.length;f+=1)l="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(q[f]),
    m|=l<<18-6*f;for(f=0;f<q.length-1;f+=1){r=g+u;for(l=r>>>2;c.length<=l;)c.push(0);c[l]|=(m>>>16-8*f&255)<<8*(t+r%4*b);g+=1}}return{value:c,binLen:8*g+d}};break;case "BYTES":c=function(a,c,d){var g,l,p,f,m,q;c=c||[0];d=d||0;p=d>>>3;q=-1===b?3:0;for(l=0;l<a.length;l+=1)g=a.charCodeAt(l),m=l+p,f=m>>>2,c.length<=f&&c.push(0),c[f]|=g<<8*(q+m%4*b);return{value:c,binLen:8*a.length+d}};break;case "ARRAYBUFFER":try{c=new ArrayBuffer(0)}catch(e){throw Error("ARRAYBUFFER not supported by this environment");}c=
    function(a,c,d){var g,l,p,f,m,q;c=c||[0];d=d||0;l=d>>>3;m=-1===b?3:0;q=new Uint8Array(a);for(g=0;g<a.byteLength;g+=1)f=g+l,p=f>>>2,c.length<=p&&c.push(0),c[p]|=q[g]<<8*(m+f%4*b);return{value:c,binLen:8*a.byteLength+d}};break;default:throw Error("format must be HEX, TEXT, B64, BYTES, or ARRAYBUFFER");}return c}function y(c,a){return c<<a|c>>>32-a}function S(c,a){return 32<a?(a-=32,new b(c.b<<a|c.a>>>32-a,c.a<<a|c.b>>>32-a)):0!==a?new b(c.a<<a|c.b>>>32-a,c.b<<a|c.a>>>32-a):c}function w(c,a){return c>>>
    a|c<<32-a}function t(c,a){var k=null,k=new b(c.a,c.b);return k=32>=a?new b(k.a>>>a|k.b<<32-a&4294967295,k.b>>>a|k.a<<32-a&4294967295):new b(k.b>>>a-32|k.a<<64-a&4294967295,k.a>>>a-32|k.b<<64-a&4294967295)}function T(c,a){var k=null;return k=32>=a?new b(c.a>>>a,c.b>>>a|c.a<<32-a&4294967295):new b(0,c.a>>>a-32)}function aa(c,a,b){return c&a^~c&b}function ba(c,a,k){return new b(c.a&a.a^~c.a&k.a,c.b&a.b^~c.b&k.b)}function U(c,a,b){return c&a^c&b^a&b}function ca(c,a,k){return new b(c.a&a.a^c.a&k.a^a.a&
    k.a,c.b&a.b^c.b&k.b^a.b&k.b)}function da(c){return w(c,2)^w(c,13)^w(c,22)}function ea(c){var a=t(c,28),k=t(c,34);c=t(c,39);return new b(a.a^k.a^c.a,a.b^k.b^c.b)}function fa(c){return w(c,6)^w(c,11)^w(c,25)}function ga(c){var a=t(c,14),k=t(c,18);c=t(c,41);return new b(a.a^k.a^c.a,a.b^k.b^c.b)}function ha(c){return w(c,7)^w(c,18)^c>>>3}function ia(c){var a=t(c,1),k=t(c,8);c=T(c,7);return new b(a.a^k.a^c.a,a.b^k.b^c.b)}function ja(c){return w(c,17)^w(c,19)^c>>>10}function ka(c){var a=t(c,19),k=t(c,61);
    c=T(c,6);return new b(a.a^k.a^c.a,a.b^k.b^c.b)}function G(c,a){var b=(c&65535)+(a&65535);return((c>>>16)+(a>>>16)+(b>>>16)&65535)<<16|b&65535}function la(c,a,b,e){var h=(c&65535)+(a&65535)+(b&65535)+(e&65535);return((c>>>16)+(a>>>16)+(b>>>16)+(e>>>16)+(h>>>16)&65535)<<16|h&65535}function H(c,a,b,e,h){var d=(c&65535)+(a&65535)+(b&65535)+(e&65535)+(h&65535);return((c>>>16)+(a>>>16)+(b>>>16)+(e>>>16)+(h>>>16)+(d>>>16)&65535)<<16|d&65535}function ma(c,a){var d,e,h;d=(c.b&65535)+(a.b&65535);e=(c.b>>>16)+
    (a.b>>>16)+(d>>>16);h=(e&65535)<<16|d&65535;d=(c.a&65535)+(a.a&65535)+(e>>>16);e=(c.a>>>16)+(a.a>>>16)+(d>>>16);return new b((e&65535)<<16|d&65535,h)}function na(c,a,d,e){var h,n,g;h=(c.b&65535)+(a.b&65535)+(d.b&65535)+(e.b&65535);n=(c.b>>>16)+(a.b>>>16)+(d.b>>>16)+(e.b>>>16)+(h>>>16);g=(n&65535)<<16|h&65535;h=(c.a&65535)+(a.a&65535)+(d.a&65535)+(e.a&65535)+(n>>>16);n=(c.a>>>16)+(a.a>>>16)+(d.a>>>16)+(e.a>>>16)+(h>>>16);return new b((n&65535)<<16|h&65535,g)}function oa(c,a,d,e,h){var n,g,l;n=(c.b&
    65535)+(a.b&65535)+(d.b&65535)+(e.b&65535)+(h.b&65535);g=(c.b>>>16)+(a.b>>>16)+(d.b>>>16)+(e.b>>>16)+(h.b>>>16)+(n>>>16);l=(g&65535)<<16|n&65535;n=(c.a&65535)+(a.a&65535)+(d.a&65535)+(e.a&65535)+(h.a&65535)+(g>>>16);g=(c.a>>>16)+(a.a>>>16)+(d.a>>>16)+(e.a>>>16)+(h.a>>>16)+(n>>>16);return new b((g&65535)<<16|n&65535,l)}function B(c,a){return new b(c.a^a.a,c.b^a.b)}function A(c){var a=[],d;if("SHA-1"===c)a=[1732584193,4023233417,2562383102,271733878,3285377520];else if(0===c.lastIndexOf("SHA-",0))switch(a=
    [3238371032,914150663,812702999,4144912697,4290775857,1750603025,1694076839,3204075428],d=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],c){case "SHA-224":break;case "SHA-256":a=d;break;case "SHA-384":a=[new b(3418070365,a[0]),new b(1654270250,a[1]),new b(2438529370,a[2]),new b(355462360,a[3]),new b(1731405415,a[4]),new b(41048885895,a[5]),new b(3675008525,a[6]),new b(1203062813,a[7])];break;case "SHA-512":a=[new b(d[0],4089235720),new b(d[1],2227873595),
    new b(d[2],4271175723),new b(d[3],1595750129),new b(d[4],2917565137),new b(d[5],725511199),new b(d[6],4215389547),new b(d[7],327033209)];break;default:throw Error("Unknown SHA variant");}else if(0===c.lastIndexOf("SHA3-",0)||0===c.lastIndexOf("SHAKE",0))for(c=0;5>c;c+=1)a[c]=[new b(0,0),new b(0,0),new b(0,0),new b(0,0),new b(0,0)];else throw Error("No SHA variants supported");return a}function K(c,a){var b=[],e,d,n,g,l,p,f;e=a[0];d=a[1];n=a[2];g=a[3];l=a[4];for(f=0;80>f;f+=1)b[f]=16>f?c[f]:y(b[f-
    3]^b[f-8]^b[f-14]^b[f-16],1),p=20>f?H(y(e,5),d&n^~d&g,l,1518500249,b[f]):40>f?H(y(e,5),d^n^g,l,1859775393,b[f]):60>f?H(y(e,5),U(d,n,g),l,2400959708,b[f]):H(y(e,5),d^n^g,l,3395469782,b[f]),l=g,g=n,n=y(d,30),d=e,e=p;a[0]=G(e,a[0]);a[1]=G(d,a[1]);a[2]=G(n,a[2]);a[3]=G(g,a[3]);a[4]=G(l,a[4]);return a}function Z(c,a,b,e){var d;for(d=(a+65>>>9<<4)+15;c.length<=d;)c.push(0);c[a>>>5]|=128<<24-a%32;a+=b;c[d]=a&4294967295;c[d-1]=a/4294967296|0;a=c.length;for(d=0;d<a;d+=16)e=K(c.slice(d,d+16),e);return e}function L(c,
    a,k){var e,h,n,g,l,p,f,m,q,u,r,t,v,w,y,A,z,x,F,B,C,D,E=[],J;if("SHA-224"===k||"SHA-256"===k)u=64,t=1,D=Number,v=G,w=la,y=H,A=ha,z=ja,x=da,F=fa,C=U,B=aa,J=d;else if("SHA-384"===k||"SHA-512"===k)u=80,t=2,D=b,v=ma,w=na,y=oa,A=ia,z=ka,x=ea,F=ga,C=ca,B=ba,J=V;else throw Error("Unexpected error in SHA-2 implementation");k=a[0];e=a[1];h=a[2];n=a[3];g=a[4];l=a[5];p=a[6];f=a[7];for(r=0;r<u;r+=1)16>r?(q=r*t,m=c.length<=q?0:c[q],q=c.length<=q+1?0:c[q+1],E[r]=new D(m,q)):E[r]=w(z(E[r-2]),E[r-7],A(E[r-15]),E[r-
    16]),m=y(f,F(g),B(g,l,p),J[r],E[r]),q=v(x(k),C(k,e,h)),f=p,p=l,l=g,g=v(n,m),n=h,h=e,e=k,k=v(m,q);a[0]=v(k,a[0]);a[1]=v(e,a[1]);a[2]=v(h,a[2]);a[3]=v(n,a[3]);a[4]=v(g,a[4]);a[5]=v(l,a[5]);a[6]=v(p,a[6]);a[7]=v(f,a[7]);return a}function D(c,a){var d,e,h,n,g=[],l=[];if(null!==c)for(e=0;e<c.length;e+=2)a[(e>>>1)%5][(e>>>1)/5|0]=B(a[(e>>>1)%5][(e>>>1)/5|0],new b(c[e+1],c[e]));for(d=0;24>d;d+=1){n=A("SHA3-");for(e=0;5>e;e+=1){h=a[e][0];var p=a[e][1],f=a[e][2],m=a[e][3],q=a[e][4];g[e]=new b(h.a^p.a^f.a^
    m.a^q.a,h.b^p.b^f.b^m.b^q.b)}for(e=0;5>e;e+=1)l[e]=B(g[(e+4)%5],S(g[(e+1)%5],1));for(e=0;5>e;e+=1)for(h=0;5>h;h+=1)a[e][h]=B(a[e][h],l[e]);for(e=0;5>e;e+=1)for(h=0;5>h;h+=1)n[h][(2*e+3*h)%5]=S(a[e][h],W[e][h]);for(e=0;5>e;e+=1)for(h=0;5>h;h+=1)a[e][h]=B(n[e][h],new b(~n[(e+1)%5][h].a&n[(e+2)%5][h].a,~n[(e+1)%5][h].b&n[(e+2)%5][h].b));a[0][0]=B(a[0][0],X[d])}return a}var d,V,W,X;d=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,
    1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,
    2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];V=[new b(d[0],3609767458),new b(d[1],602891725),new b(d[2],3964484399),new b(d[3],2173295548),new b(d[4],4081628472),new b(d[5],3053834265),new b(d[6],2937671579),new b(d[7],3664609560),new b(d[8],2734883394),new b(d[9],1164996542),new b(d[10],1323610764),new b(d[11],3590304994),new b(d[12],4068182383),new b(d[13],991336113),new b(d[14],633803317),new b(d[15],3479774868),new b(d[16],2666613458),new b(d[17],944711139),new b(d[18],2341262773),
    new b(d[19],2007800933),new b(d[20],1495990901),new b(d[21],1856431235),new b(d[22],3175218132),new b(d[23],2198950837),new b(d[24],3999719339),new b(d[25],766784016),new b(d[26],2566594879),new b(d[27],3203337956),new b(d[28],1034457026),new b(d[29],2466948901),new b(d[30],3758326383),new b(d[31],168717936),new b(d[32],1188179964),new b(d[33],1546045734),new b(d[34],1522805485),new b(d[35],2643833823),new b(d[36],2343527390),new b(d[37],1014477480),new b(d[38],1206759142),new b(d[39],344077627),
    new b(d[40],1290863460),new b(d[41],3158454273),new b(d[42],3505952657),new b(d[43],106217008),new b(d[44],3606008344),new b(d[45],1432725776),new b(d[46],1467031594),new b(d[47],851169720),new b(d[48],3100823752),new b(d[49],1363258195),new b(d[50],3750685593),new b(d[51],3785050280),new b(d[52],3318307427),new b(d[53],3812723403),new b(d[54],2003034995),new b(d[55],3602036899),new b(d[56],1575990012),new b(d[57],1125592928),new b(d[58],2716904306),new b(d[59],442776044),new b(d[60],593698344),new b(d[61],
    3733110249),new b(d[62],2999351573),new b(d[63],3815920427),new b(3391569614,3928383900),new b(3515267271,566280711),new b(3940187606,3454069534),new b(4118630271,4000239992),new b(116418474,1914138554),new b(174292421,2731055270),new b(289380356,3203993006),new b(460393269,320620315),new b(685471733,587496836),new b(852142971,1086792851),new b(1017036298,365543100),new b(1126000580,2618297676),new b(1288033470,3409855158),new b(1501505948,4234509866),new b(1607167915,987167468),new b(1816402316,
    1246189591)];X=[new b(0,1),new b(0,32898),new b(2147483648,32906),new b(2147483648,2147516416),new b(0,32907),new b(0,2147483649),new b(2147483648,2147516545),new b(2147483648,32777),new b(0,138),new b(0,136),new b(0,2147516425),new b(0,2147483658),new b(0,2147516555),new b(2147483648,139),new b(2147483648,32905),new b(2147483648,32771),new b(2147483648,32770),new b(2147483648,128),new b(0,32778),new b(2147483648,2147483658),new b(2147483648,2147516545),new b(2147483648,32896),new b(0,2147483649),
    new b(2147483648,2147516424)];W=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]];"function"===typeof define&&define.amd?define(function(){return C}):"undefined"!==typeof exports?("undefined"!==typeof module&&module.exports&&(module.exports=C),exports=C):Y.jsSHA=C})(this);
    //}

    window.Modernizr = function (ay, ax, aw) {
        function U(b) {
            ao.cssText = b
        }

        function T(d, c) {
            return U(ak.join(d + ";") + (c || ""))
        }

        function S(d, c) {
            return typeof d === c
        }

        function R(d, c) {
            return !!~("" + d).indexOf(c)
        }

        function Q(f, c) {
            for (var h in f) {
                var g = f[h];
                if (!R(g, "-") && ao[g] !== aw) {
                    return c == "pfx" ? g : !0
                }
            }
            return !1
        }

        function P(g, c, j) {
            for (var i in g) {
                var h = c[g[i]];
                if (h !== aw) {
                    return j === !1 ? g[i] : S(h, "function") ? h.bind(j || c) : h
                }
            }
            return !1
        }

        function O(g, f, j) {
            var i = g.charAt(0).toUpperCase() + g.slice(1), h = (g + " " + ai.join(i + " ") + i).split(" ");
            return S(f, "string") || S(f, "undefined") ? Q(h, f) : (h = (g + " " + ah.join(i + " ") + i).split(" "), P(h, f, j))
        }

        function N() {
            au.input = function (f) {
                for (var b = 0, a = f.length;
                     b < a;
                     b++) {
                    ad[f[b]] = f[b] in an
                }
                return ad.list && (ad.list = !!ax.createElement("datalist") && !!ay.HTMLDataListElement), ad
            }("autocomplete autofocus list placeholder max min multiple pattern required step".split(" ")), au.inputtypes = function (b) {
                for (var l = 0, k, j, g, c = b.length;
                     l < c;
                     l++) {
                    an.setAttribute("type", j = b[l]), k = an.type !== "text", k && (an.value = am, an.style.cssText = "position:absolute;visibility:hidden;", /^range$/.test(j) && an.style.WebkitAppearance !== aw ? (ar.appendChild(an), g = ax.defaultView, k = g.getComputedStyle && g.getComputedStyle(an, null).WebkitAppearance !== "textfield" && an.offsetHeight !== 0, ar.removeChild(an)) : /^(search|tel)$/.test(j) || (/^(url|email)$/.test(j) ? k = an.checkValidity && an.checkValidity() === !1 : k = an.value != am)), ae[b[l]] = !!k
                }
                return ae
            }("search tel url email datetime date month week time datetime-local number range color".split(" "))
        }

        var av = "2.8.3", au = {}, at = !0, ar = ax.documentElement, aq = "modernizr", ap = ax.createElement(aq), ao = ap.style, an = ax.createElement("input"), am = ":)", al = {}.toString, ak = " -webkit- -moz- -o- -ms- ".split(" "), aj = "Webkit Moz O ms", ai = aj.split(" "), ah = aj.toLowerCase().split(" "), ag = {svg: "http://www.w3.org/2000/svg"}, af = {}, ae = {}, ad = {}, ac = [], ab = ac.slice, aa, Z = function (v, u, t, s) {
            var r, q, p, o, h = ax.createElement("div"), g = ax.body, b = g || ax.createElement("body");
            if (parseInt(t, 10)) {
                while (t--) {
                    p = ax.createElement("div"), p.id = s ? s[t] : aq + (t + 1), h.appendChild(p)
                }
            }
            return r = ["&#173;", '<style id="s', aq, '">', v, "</style>"].join(""), h.id = aq, (g ? h : b).innerHTML += r, b.appendChild(h), g || (b.style.background = "", b.style.overflow = "hidden", o = ar.style.overflow, ar.style.overflow = "hidden", ar.appendChild(b)), q = u(h, v), g ? h.parentNode.removeChild(h) : (b.parentNode.removeChild(b), ar.style.overflow = o), !!q
        }, Y = function (a) {
            var f = ay.matchMedia || ay.msMatchMedia;
            if (f) {
                return f(a) && f(a).matches || !1
            }
            var e;
            return Z("@media " + a + " { #" + aq + " { position: absolute; } }", function (c) {
                e = (ay.getComputedStyle ? getComputedStyle(c, null) : c.currentStyle)["position"] == "absolute"
            }), e
        }, X = function () {
            function c(h, g) {
                g = g || ax.createElement(b[h] || "div"), h = "on" + h;
                var a = h in g;
                return a || (g.setAttribute || (g = ax.createElement("div")), g.setAttribute && g.removeAttribute && (g.setAttribute(h, ""), a = S(g[h], "function"), S(g[h], "undefined") || (g[h] = aw), g.removeAttribute(h))), g = null, a
            }

            var b = {
                select: "input",
                change: "input",
                submit: "form",
                reset: "form",
                error: "img",
                load: "img",
                abort: "img"
            };
            return c
        }(), W = {}.hasOwnProperty, V;
        !S(W, "undefined") && !S(W.call, "undefined") ? V = function (d, c) {
            return W.call(d, c)
        } : V = function (d, c) {
            return c in d && S(d.constructor.prototype[c], "undefined")
        }, Function.prototype.bind || (Function.prototype.bind = function (a) {
            var h = this;
            if (typeof h != "function") {
                throw new TypeError
            }
            var g = ab.call(arguments, 1), f = function () {
                if (this instanceof f) {
                    var b = function () {
                    };
                    b.prototype = h.prototype;
                    var d = new b, c = h.apply(d, g.concat(ab.call(arguments)));
                    return Object(c) === c ? c : d
                }
                return h.apply(a, g.concat(ab.call(arguments)))
            };
            return f
        }), af.flexbox = function () {
            return O("flexWrap")
        }, af.flexboxlegacy = function () {
            return O("boxDirection")
        }, af.canvas = function () {
            var b = ax.createElement("canvas");
            return !!b.getContext && !!b.getContext("2d")
        }, af.canvastext = function () {
            return !!au.canvas && !!S(ax.createElement("canvas").getContext("2d").fillText, "function")
        }, af.touch = function () {
            var a;
            return "ontouchstart" in ay || ay.DocumentTouch && ax instanceof DocumentTouch ? a = !0 : Z(["@media (", ak.join("touch-enabled),("), aq, ")", "{#modernizr{top:9px;position:absolute}}"].join(""), function (b) {
                a = b.offsetTop === 9
            }), a
        }, af.postmessage = function () {
            return !!ay.postMessage
        }, af.websqldatabase = function () {
            return !!ay.openDatabase
        }, af.indexedDB = function () {
            return !!O("indexedDB", ay)
        }, af.hashchange = function () {
            return X("hashchange", ay) && (ax.documentMode === aw || ax.documentMode > 7)
        }, af.history = function () {
            return !!ay.history && !!history.pushState
        }, af.draganddrop = function () {
            var b = ax.createElement("div");
            return "draggable" in b || "ondragstart" in b && "ondrop" in b
        }, af.websockets = function () {
            return "WebSocket" in ay || "MozWebSocket" in ay
        }, af.rgba = function () {
            return U("background-color:rgba(150,255,150,.5)"), R(ao.backgroundColor, "rgba")
        }, af.hsla = function () {
            return U("background-color:hsla(120,40%,100%,.5)"), R(ao.backgroundColor, "rgba") || R(ao.backgroundColor, "hsla")
        }, af.multiplebgs = function () {
            return U("background:url(https://),url(https://),red url(https://)"), /(url\s*\(.*?){3}/.test(ao.background)
        }, af.backgroundsize = function () {
            return O("backgroundSize")
        }, af.borderimage = function () {
            return O("borderImage")
        }, af.borderradius = function () {
            return O("borderRadius")
        }, af.boxshadow = function () {
            return O("boxShadow")
        }, af.textshadow = function () {
            return ax.createElement("div").style.textShadow === ""
        }, af.opacity = function () {
            return T("opacity:.55"), /^0.55$/.test(ao.opacity)
        }, af.cssanimations = function () {
            return O("animationName")
        }, af.csscolumns = function () {
            return O("columnCount")
        }, af.cssgradients = function () {
            var e = "background-image:", d = "gradient(linear,left top,right bottom,from(#9f9),to(white));", f = "linear-gradient(left top,#9f9, white);";
            return U((e + "-webkit- ".split(" ").join(d + e) + ak.join(f + e)).slice(0, -e.length)), R(ao.backgroundImage, "gradient")
        }, af.cssreflections = function () {
            return O("boxReflect")
        }, af.csstransforms = function () {
            return !!O("transform")
        }, af.csstransforms3d = function () {
            var b = !!O("perspective");
            return b && "webkitPerspective" in ar.style && Z("@media (transform-3d),(-webkit-transform-3d){#modernizr{left:9px;position:absolute;height:3px;}}", function (a, d) {
                b = a.offsetLeft === 9 && a.offsetHeight === 3
            }), b
        }, af.csstransitions = function () {
            return O("transition")
        }, af.fontface = function () {
            var b;
            return Z('@font-face {font-family:"font";src:url("https://")}', function (k, j) {
                var i = ax.getElementById("smodernizr"), h = i.sheet || i.styleSheet, a = h ? h.cssRules && h.cssRules[0] ? h.cssRules[0].cssText : h.cssText || "" : "";
                b = /src/i.test(a) && a.indexOf(j.split(" ")[0]) === 0
            }), b
        }, af.generatedcontent = function () {
            var b;
            return Z(["#", aq, "{font:0/0 a}#", aq, ':after{content:"', am, '";visibility:hidden;font:3px/1 a}'].join(""), function (a) {
                b = a.offsetHeight >= 3
            }), b
        }, af.video = function () {
            var b = ax.createElement("video"), f = !1;
            try {
                if (f = !!b.canPlayType) {
                    f = new Boolean(f), f.ogg = b.canPlayType('video/ogg; codecs="theora"').replace(/^no$/, ""), f.h264 = b.canPlayType('video/mp4; codecs="avc1.42E01E"').replace(/^no$/, ""), f.webm = b.canPlayType('video/webm; codecs="vp8, vorbis"').replace(/^no$/, "")
                }
            } catch (e) {
            }
            return f
        }, af.audio = function () {
            var b = ax.createElement("audio"), f = !1;
            try {
                if (f = !!b.canPlayType) {
                    f = new Boolean(f), f.ogg = b.canPlayType('audio/ogg; codecs="vorbis"').replace(/^no$/, ""), f.mp3 = b.canPlayType("audio/mpeg;").replace(/^no$/, ""), f.wav = b.canPlayType('audio/wav; codecs="1"').replace(/^no$/, ""), f.m4a = (b.canPlayType("audio/x-m4a;") || b.canPlayType("audio/aac;")).replace(/^no$/, "")
                }
            } catch (e) {
            }
            return f
        }, af.localstorage = function () {
            try {
                return localStorage.setItem(aq, aq), localStorage.removeItem(aq), !0
            } catch (b) {
                return !1
            }
        }, af.sessionstorage = function () {
            try {
                return sessionStorage.setItem(aq, aq), sessionStorage.removeItem(aq), !0
            } catch (b) {
                return !1
            }
        }, af.webworkers = function () {
            return !!ay.Worker
        }, af.applicationcache = function () {
            return !!ay.applicationCache
        }, af.svg = function () {
            return !!ax.createElementNS && !!ax.createElementNS(ag.svg, "svg").createSVGRect
        };
        for (var M in af) {
            V(af, M) && (aa = M.toLowerCase(), au[aa] = af[M](), ac.push((au[aa] ? "" : "no-") + aa))
        }
        return au.input || N(), au.addTest = function (e, c) {
            if (typeof e == "object") {
                for (var f in e) {
                    V(e, f) && au.addTest(f, e[f])
                }
            } else {
                e = e.toLowerCase();
                if (au[e] !== aw) {
                    return au
                }
                c = typeof c == "function" ? c() : c, typeof at != "undefined" && at && (ar.className += " " + (c ? "" : "no-") + e), au[e] = c
            }
            return au
        }, U(""), ap = an = null, au._version = av, au._prefixes = ak, au._domPrefixes = ah, au._cssomPrefixes = ai, au.mq = Y, au.hasEvent = X, au.testProp = function (b) {
            return Q([b])
        }, au.testAllProps = O, au.testStyles = Z, ar.className = ar.className.replace(/(^|\s)no-js(\s|$)/, "$1$2") + (at ? " js " + ac.join(" ") : ""), au
    }(this, this.document), function (ab, aa) {
        function Q(f, e) {
            var h = f.createElement("p"), g = f.getElementsByTagName("head")[0] || f.documentElement;
            return h.innerHTML = "x<style>" + e + "</style>", g.insertBefore(h.lastChild, g.firstChild)
        }

        function P() {
            var b = I.elements;
            return typeof b == "string" ? b.split(" ") : b
        }

        function O(d) {
            var c = S[d[U]];
            return c || (c = {}, T++, d[U] = T, S[T] = c), c
        }

        function N(b, h, f) {
            h || (h = aa);
            if (R) {
                return h.createElement(b)
            }
            f || (f = O(h));
            var e;
            return f.cache[b] ? e = f.cache[b].cloneNode() : W.test(b) ? e = (f.cache[b] = f.createElem(b)).cloneNode() : e = f.createElem(b), e.canHaveChildren && !X.test(b) && !e.tagUrn ? f.frag.appendChild(e) : e
        }

        function M(b, l) {
            b || (b = aa);
            if (R) {
                return b.createDocumentFragment()
            }
            l = l || O(b);
            var k = l.frag.cloneNode(), j = 0, i = P(), h = i.length;
            for (;
                j < h;
                j++) {
                k.createElement(i[j])
            }
            return k
        }

        function K(d, c) {
            c.cache || (c.cache = {}, c.createElem = d.createElement, c.createFrag = d.createDocumentFragment, c.frag = c.createFrag()), d.createElement = function (a) {
                return I.shivMethods ? N(a, d, c) : c.createElem(a)
            }, d.createDocumentFragment = Function("h,f", "return function(){var n=f.cloneNode(),c=n.createElement;h.shivMethods&&(" + P().join().replace(/\w+/g, function (b) {
                    return c.createElem(b), c.frag.createElement(b), 'c("' + b + '")'
                }) + ");return n}")(I, c.frag)
        }

        function J(b) {
            b || (b = aa);
            var d = O(b);
            return I.shivCSS && !V && !d.hasCSS && (d.hasCSS = !!Q(b, "article,aside,dialog,figcaption,figure,footer,header,hgroup,main,nav,section{display:block}mark{background:#FF0;color:#000}template{display:none}")), R || K(b, d), b
        }

        function E(h) {
            var g, l = h.getElementsByTagName("*"), k = l.length, j = RegExp("^(?:" + P().join("|") + ")$", "i"), i = [];
            while (k--) {
                g = l[k], j.test(g.nodeName) && i.push(g.applyElement(D(g)))
            }
            return i
        }

        function D(g) {
            var f, j = g.attributes, i = j.length, h = g.ownerDocument.createElement(G + ":" + g.nodeName);
            while (i--) {
                f = j[i], f.specified && h.setAttribute(f.nodeName, f.nodeValue)
            }
            return h.style.cssText = g.style.cssText, h
        }

        function C(h) {
            var g, l = h.split("{"), k = l.length, j = RegExp("(^|[\\s,>+~])(" + P().join("|") + ")(?=[[\\s,>+~#.:]|$)", "gi"), i = "$1" + G + "\\:$2";
            while (k--) {
                g = l[k] = l[k].split("}"), g[g.length - 1] = g[g.length - 1].replace(j, i), l[k] = g.join("}")
            }
            return l.join("{")
        }

        function B(d) {
            var c = d.length;
            while (c--) {
                d[c].removeNode()
            }
        }

        function L(i) {
            function j() {
                clearTimeout(m._removeSheetTimer), h && h.removeNode(!0), h = null
            }

            var h, n, m = O(i), l = i.namespaces, k = i.parentWindow;
            return !F || i.printShived ? i : (typeof l[G] == "undefined" && l.add(G), k.attachEvent("onbeforeprint", function () {
                j();
                var r, q, p, o = i.styleSheets, g = [], c = o.length, b = Array(c);
                while (c--) {
                    b[c] = o[c]
                }
                while (p = b.pop()) {
                    if (!p.disabled && H.test(p.media)) {
                        try {
                            r = p.imports, q = r.length
                        } catch (a) {
                            q = 0
                        }
                        for (c = 0;
                             c < q;
                             c++) {
                            b.push(r[c])
                        }
                        try {
                            g.push(p.cssText)
                        } catch (a) {
                        }
                    }
                }
                g = C(g.reverse().join("")), n = E(i), h = Q(i, g)
            }), k.attachEvent("onafterprint", function () {
                B(n), clearTimeout(m._removeSheetTimer), m._removeSheetTimer = setTimeout(j, 500)
            }), i.printShived = !0, i)
        }

        var Z = "3.7.0", Y = ab.html5 || {}, X = /^<|^(?:button|map|select|textarea|object|iframe|option|optgroup)$/i, W = /^(?:a|b|code|div|fieldset|h1|h2|h3|h4|h5|h6|i|label|li|ol|p|q|span|strong|style|table|tbody|td|th|tr|ul)$/i, V, U = "_html5shiv", T = 0, S = {}, R;
        (function () {
            try {
                var b = aa.createElement("a");
                b.innerHTML = "<xyz></xyz>", V = "hidden" in b, R = b.childNodes.length == 1 || function () {
                        aa.createElement("a");
                        var c = aa.createDocumentFragment();
                        return typeof c.cloneNode == "undefined" || typeof c.createDocumentFragment == "undefined" || typeof c.createElement == "undefined"
                    }()
            } catch (d) {
                V = !0, R = !0
            }
        })();
        var I = {
            elements: Y.elements || "abbr article aside audio bdi canvas data datalist details dialog figcaption figure footer header hgroup main mark meter nav output progress section summary template time video",
            version: Z,
            shivCSS: Y.shivCSS !== !1,
            supportsUnknownElements: R,
            shivMethods: Y.shivMethods !== !1,
            type: "default",
            shivDocument: J,
            createElement: N,
            createDocumentFragment: M
        };
        ab.html5 = I, J(aa);
        var H = /^$|\b(?:all|print)\b/, G = "html5shiv", F = !R && function () {
                var a = aa.documentElement;
                return typeof aa.namespaces != "undefined" && typeof aa.parentWindow != "undefined" && typeof a.applyElement != "undefined" && typeof a.removeNode != "undefined" && typeof ab.attachEvent != "undefined"
            }();
        I.type += " print", I.shivPrint = L, L(aa)
    }(this, document), function (ad, ac, ab) {
        function aa(b) {
            return "[object Function]" == P.call(b)
        }

        function Z(b) {
            return "string" == typeof b
        }

        function Y() {
        }

        function X(b) {
            return !b || "loaded" == b || "complete" == b || "uninitialized" == b
        }

        function W() {
            var b = O.shift();
            M = 1, b ? b.t ? R(function () {
                ("c" == b.t ? L.injectCss : L.injectJs)(b.s, 0, b.a, b.x, b.e, 1)
            }, 0) : (b(), W()) : M = 0
        }

        function V(w, v, t, s, q, p, n) {
            function m(a) {
                if (!g && X(h.readyState) && (x.r = g = 1, !M && W(), h.onload = h.onreadystatechange = null, a)) {
                    "img" != w && R(function () {
                        I.removeChild(h)
                    }, 50);
                    for (var c in D[v]) {
                        D[v].hasOwnProperty(c) && D[v][c].onload()
                    }
                }
            }

            var n = n || L.errorTimeout, h = ac.createElement(w), g = 0, b = 0, x = {t: t, s: v, e: q, a: p, x: n};
            1 === D[v] && (b = 1, D[v] = []), "object" == w ? h.data = v : (h.src = v, h.type = w), h.width = h.height = "0", h.onerror = h.onload = h.onreadystatechange = function () {
                m.call(this, b)
            }, O.splice(s, 0, x), "img" != w && (b || 2 === D[v] ? (I.insertBefore(h, J ? null : Q), R(m, n)) : D[v].push(h))
        }

        function U(g, e, j, i, h) {
            return M = 0, e = e || "j", Z(g) ? V("c" == e ? G : H, g, e, this.i++, j, i, h) : (O.splice(this.i++, 0, g), 1 == O.length && W()), this
        }

        function T() {
            var b = L;
            return b.loader = {load: U, i: 0}, b
        }

        var S = ac.documentElement, R = ad.setTimeout, Q = ac.getElementsByTagName("script")[0], P = {}.toString, O = [], M = 0, K = "MozAppearance" in S.style, J = K && !!ac.createRange().compareNode, I = J ? S : Q.parentNode, S = ad.opera && "[object Opera]" == P.call(ad.opera), S = !!ac.attachEvent && !S, H = K ? "object" : S ? "script" : "img", G = S ? "script" : H, F = Array.isArray || function (b) {
                return "[object Array]" == P.call(b)
            }, E = [], D = {}, C = {
            timeout: function (d, c) {
                return c.length && (d.timeout = c[0]), d
            }
        }, N, L;
        L = function (e) {
            function c(i) {
                var i = i.split("!"), h = E.length, q = i.pop(), p = i.length, q = {
                    url: q,
                    origUrl: q,
                    prefixes: i
                }, o, l, j;
                for (l = 0;
                     l < p;
                     l++) {
                    j = i[l].split("="), (o = C[j.shift()]) && (q = o(q, j))
                }
                for (l = 0;
                     l < h;
                     l++) {
                    q = E[l](q)
                }
                return q
            }

            function n(b, s, r, q, p) {
                var o = c(b), l = o.autoCallback;
                o.url.split(".").pop().split("?").shift(), o.bypass || (s && (s = aa(s) ? s : s[b] || s[q] || s[b.split("/").pop().split("?")[0]]), o.instead ? o.instead(b, s, r, q, p) : (D[o.url] ? o.noexec = !0 : D[o.url] = 1, r.load(o.url, o.forceCSS || !o.forceJS && "css" == o.url.split(".").pop().split("?").shift() ? "c" : ab, o.noexec, o.attrs, o.timeout), (aa(s) || aa(l)) && r.load(function () {
                    T(), s && s(o.origUrl, p, q), l && l(o.origUrl, p, q), D[o.url] = 2
                })))
            }

            function m(w, v) {
                function u(b, h) {
                    if (b) {
                        if (Z(b)) {
                            h || (r = function () {
                                var i = [].slice.call(arguments);
                                q.apply(this, i), p()
                            }), n(b, r, v, 0, t)
                        } else {
                            if (Object(b) === b) {
                                for (g in o = function () {
                                    var a = 0, i;
                                    for (i in b) {
                                        b.hasOwnProperty(i) && a++
                                    }
                                    return a
                                }(), b) {
                                    b.hasOwnProperty(g) && (!h && !--o && (aa(r) ? r = function () {
                                        var i = [].slice.call(arguments);
                                        q.apply(this, i), p()
                                    } : r[g] = function (i) {
                                        return function () {
                                            var a = [].slice.call(arguments);
                                            i && i.apply(this, a), p()
                                        }
                                    }(q[g])), n(b[g], r, v, g, t))
                                }
                            }
                        }
                    } else {
                        !h && p()
                    }
                }

                var t = !!w.test, s = w.load || w.both, r = w.callback || Y, q = r, p = w.complete || Y, o, g;
                u(t ? w.yep : w.nope, !!s), s && u(s)
            }

            var k, f, d = this.yepnope.loader;
            if (Z(e)) {
                n(e, 0, d, 0)
            } else {
                if (F(e)) {
                    for (k = 0;
                         k < e.length;
                         k++) {
                        f = e[k], Z(f) ? n(f, 0, d, 0) : F(f) ? L(f) : Object(f) === f && m(f, d)
                    }
                } else {
                    Object(e) === e && m(e, d)
                }
            }
        }, L.addPrefix = function (d, c) {
            C[d] = c
        }, L.addFilter = function (b) {
            E.push(b)
        }, L.errorTimeout = 10000, null == ac.readyState && ac.addEventListener && (ac.readyState = "loading", ac.addEventListener("DOMContentLoaded", N = function () {
            ac.removeEventListener("DOMContentLoaded", N, 0), ac.readyState = "complete"
        }, 0)), ad.yepnope = T(), ad.yepnope.executeStack = W, ad.yepnope.injectJs = function (r, q, p, n, m, h) {
            var g = ac.createElement("script"), f, b, n = n || L.errorTimeout;
            g.src = r;
            for (b in p) {
                g.setAttribute(b, p[b])
            }
            q = h ? W : q || Y, g.onreadystatechange = g.onload = function () {
                !f && X(g.readyState) && (f = 1, q(), g.onload = g.onreadystatechange = null)
            }, R(function () {
                f || (f = 1, q(1))
            }, n), m ? g.onload() : Q.parentNode.insertBefore(g, Q)
        }, ad.yepnope.injectCss = function (b, n, m, l, k, h) {
            var l = ac.createElement("link"), f, n = h ? W : n || Y;
            l.href = b, l.rel = "stylesheet", l.type = "text/css";
            for (f in m) {
                l.setAttribute(f, m[f])
            }
            k || (Q.parentNode.insertBefore(l, Q), R(n, 0))
        }
    }(this, document), Modernizr.load = function () {
        yepnope.apply(window, [].slice.call(arguments, 0))
    };

    /**
     * Agenda
     *
     * This file contains definitions for:
     * NSCR.fn
     * NSCR.gigyaService
     * $.fn.createSocialShareBarItem
     * $.fn.createLiveChat
     * NSCR.siteTracking
     * onSubmitButtonClicked
     * newsletterSignup
     * showPageWrapper
     * makeMobileScreenScrollable
     * callService
     * setUserSubscription
     * retrieveProfileInfo
     * reloadCurrentPage
     * loginEventHandler
     * deleteProfileInfo
     * showLoginRegisterLinks
     * logoutEventHandler
     * getAccountInfoResponse
     * isUserLoggedIn
     * loadGigyaScreen
     * uploadProfilePicToS3Bucket
     * getURLParameter
     * handleUserState
     * getEntitleAndPrefFromCookie
     * hideMyProfileLink
     * hideLoginRegisterLinks
     * showMyProfileLink
     * @type {*|{}}
     */
     var MD5 = function(d){var r = M(V(Y(X(d),8*d.length)));return r.toLowerCase()};function M(d){for(var _,m="0123456789ABCDEF",f="",r=0;r<d.length;r++)_=d.charCodeAt(r),f+=m.charAt(_>>>4&15)+m.charAt(15&_);return f}function X(d){for(var _=Array(d.length>>2),m=0;m<_.length;m++)_[m]=0;for(m=0;m<8*d.length;m+=8)_[m>>5]|=(255&d.charCodeAt(m/8))<<m%32;return _}function V(d){for(var _="",m=0;m<32*d.length;m+=8)_+=String.fromCharCode(d[m>>5]>>>m%32&255);return _}function Y(d,_){d[_>>5]|=128<<_%32,d[14+(_+64>>>9<<4)]=_;for(var m=1732584193,f=-271733879,r=-1732584194,i=271733878,n=0;n<d.length;n+=16){var h=m,t=f,g=r,e=i;f=md5_ii(f=md5_ii(f=md5_ii(f=md5_ii(f=md5_hh(f=md5_hh(f=md5_hh(f=md5_hh(f=md5_gg(f=md5_gg(f=md5_gg(f=md5_gg(f=md5_ff(f=md5_ff(f=md5_ff(f=md5_ff(f,r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+0],7,-680876936),f,r,d[n+1],12,-389564586),m,f,d[n+2],17,606105819),i,m,d[n+3],22,-1044525330),r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+4],7,-176418897),f,r,d[n+5],12,1200080426),m,f,d[n+6],17,-1473231341),i,m,d[n+7],22,-45705983),r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+8],7,1770035416),f,r,d[n+9],12,-1958414417),m,f,d[n+10],17,-42063),i,m,d[n+11],22,-1990404162),r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+12],7,1804603682),f,r,d[n+13],12,-40341101),m,f,d[n+14],17,-1502002290),i,m,d[n+15],22,1236535329),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+1],5,-165796510),f,r,d[n+6],9,-1069501632),m,f,d[n+11],14,643717713),i,m,d[n+0],20,-373897302),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+5],5,-701558691),f,r,d[n+10],9,38016083),m,f,d[n+15],14,-660478335),i,m,d[n+4],20,-405537848),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+9],5,568446438),f,r,d[n+14],9,-1019803690),m,f,d[n+3],14,-187363961),i,m,d[n+8],20,1163531501),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+13],5,-1444681467),f,r,d[n+2],9,-51403784),m,f,d[n+7],14,1735328473),i,m,d[n+12],20,-1926607734),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+5],4,-378558),f,r,d[n+8],11,-2022574463),m,f,d[n+11],16,1839030562),i,m,d[n+14],23,-35309556),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+1],4,-1530992060),f,r,d[n+4],11,1272893353),m,f,d[n+7],16,-155497632),i,m,d[n+10],23,-1094730640),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+13],4,681279174),f,r,d[n+0],11,-358537222),m,f,d[n+3],16,-722521979),i,m,d[n+6],23,76029189),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+9],4,-640364487),f,r,d[n+12],11,-421815835),m,f,d[n+15],16,530742520),i,m,d[n+2],23,-995338651),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+0],6,-198630844),f,r,d[n+7],10,1126891415),m,f,d[n+14],15,-1416354905),i,m,d[n+5],21,-57434055),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+12],6,1700485571),f,r,d[n+3],10,-1894986606),m,f,d[n+10],15,-1051523),i,m,d[n+1],21,-2054922799),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+8],6,1873313359),f,r,d[n+15],10,-30611744),m,f,d[n+6],15,-1560198380),i,m,d[n+13],21,1309151649),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+4],6,-145523070),f,r,d[n+11],10,-1120210379),m,f,d[n+2],15,718787259),i,m,d[n+9],21,-343485551),m=safe_add(m,h),f=safe_add(f,t),r=safe_add(r,g),i=safe_add(i,e)}return Array(m,f,r,i)}function md5_cmn(d,_,m,f,r,i){return safe_add(bit_rol(safe_add(safe_add(_,d),safe_add(f,i)),r),m)}function md5_ff(d,_,m,f,r,i,n){return md5_cmn(_&m|~_&f,d,_,r,i,n)}function md5_gg(d,_,m,f,r,i,n){return md5_cmn(_&f|m&~f,d,_,r,i,n)}function md5_hh(d,_,m,f,r,i,n){return md5_cmn(_^m^f,d,_,r,i,n)}function md5_ii(d,_,m,f,r,i,n){return md5_cmn(m^(_|~f),d,_,r,i,n)}function safe_add(d,_){var m=(65535&d)+(65535&_);return(d>>16)+(_>>16)+(m>>16)<<16|65535&m}function bit_rol(d,_){return d<<_|d>>>32-_};

    // NASCAR namespace as a global variable
    var NSCR = NSCR || {};

    jQuery.extend(NSCR, {
        eventTarget: jQuery('body'), //[confirmed]
        login: { // [confirmed]
            status: null,
            data: {},
            idmUserName: null,
            ssoState: null,
            idmUserID: null, // [confirmed]
            idmUserType: null,
            livefyreToken: null, // [confirmed]
            favDriver: null, // [confirmed]
            favDriverID: null // [confirmed]
        },
        userEntitleAndPref: {} // [confirmed]
    });

    /**
     * Some Global methods and properties available with NSCR Object.
     *
     * NSCR.fn namespace definition
     */
    (function ($, window, document, undefined) {
        NSCR.fn = {

            /**
             * This method will return the current Viewport size.
             */
            getViewportSize: function() { // [confirmed]
                var size = [0, 0];
                if (typeof window.innerWidth != 'undefined') {
                    size = [window.innerWidth, window.innerHeight];
                } else if (typeof document.documentElement != 'undefined' && typeof document.documentElement.clientWidth != 'undefined' && document.documentElement.clientWidth != 0) {
                    size = [document.documentElement.clientWidth, document.documentElement.clientHeight];
                } else {
                    size = [document.getElementsByTagName('body')[0].clientWidth, document.getElementsByTagName('body')[0].clientHeight];
                }
                return size;
            },

            createCookie: function (name, value, days, path, domain) { // [confirmed]
                if(name.length == 0){return}
                var expires;
                if (days) {
                    var date = new Date();
                    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
                    expires = "; expires=" + date.toGMTString();
                } else {
                    expires = "";
                }

                document.cookie = name + "=" + value + expires + "; path=" + path + "; domain=" + domain;
            },

            readCookie: function (name) { // [confirmed]
                if(name.length == 0){return null}
                var cName = name + "=",
                    cArray = document.cookie.split(';'),
                    cACount = cArray.length;

                while (cACount) {
                    cACount--;
                    var c = cArray[cACount];
                    while (c.charAt(0) == ' ') c = c.substring(1, c.length);
                    if (c.indexOf(cName) == 0) return c.substring(cName.length, c.length);
                }

                return null;
            },

            deleteCookie: function (name, domain) { // [confirmed]
                if(name.length == 0){return}
                NSCR.fn.createCookie(name, "", -1, "/", domain);
            },

            /**
             * getUrl
             *
             * function to get a string from the NSCR.config.url object
             *
             * @param key: String: the child object to look for in the NSCR.config.url object (ie: "getUserAccount");
             *
             * @returns String - either the value we're looking for, or empty quotes "" if the value can't be found
             */
            getUrl: function (key, wildcards) { //[confirmed]

                var returnString;
                wildcards = wildcards || [];

                try {
                    returnString = eval("NSCR.config.url." + key + "['" + NSCR.config.envir + "']");
                    if (wildcards.length > 0) {
                        var re = new RegExp(/\[\$\]/g);
                        var i = 0;
                        returnString = returnString.replace(re, function (m, key, value) {
                            m = (wildcards[i] != undefined) ? wildcards[i] : "";
                            i++;
                            return m;
                        });
                    }
                } catch (err) {

                    returnString = eval("NSCR.config.url.defaultPath['" + NSCR.config.envir + "']");
                }
                return returnString;

            },

            /**
             * Method can be used to create an Object of all the Query String Parameters into URL.
             */
            parseQuerystring: function (doNotDecode, sBaseStringParam) { // [confirmed]
                var sBaseString = $.trim( (sBaseStringParam || location.search).replace('?', '') ),
                    querystring = [];

                if ( sBaseString.length > 0 ){
                    querystring = sBaseString.split('&');
                }
                //we may have data in the query string
                var queryObj = {},
                    i, iLen, name, value;

                iLen = querystring.length;

                // loop through each name-value pair and populate object
                for (i = 0; i < iLen; i++) {
                    // get name and value
                    name = querystring[i].split('=')[0];
                    value = (doNotDecode) ? querystring[i].split('=')[1] : decodeURIComponent(querystring[i].split('=')[1]);
                    // populate object
                    if ( queryObj[name] ){
                        if ( NSCR.fn.typeOf(queryObj[name]) == "array" ){
                            if ( queryObj[name].indexOf(value) == -1 ){
                                queryObj[name].push(value);
                            }
                        } else {
                            queryObj[name] = [queryObj[name]].concat([value]);
                        }
                    } else {
                        queryObj[name] = value;
                    }
                }
                return queryObj;
            },

            hasProperty: function(obj, key) { //[confirmed]
                return Object.prototype.hasOwnProperty.call(obj, key);
            },

            typeOf: (function toType(global) { // [confirmed]
                return function (obj) {
                    if (obj === global) return "global";
                    return ({}).toString.call(obj).match(/\s([a-z|A-Z]+)/)[1].toLowerCase();
                };
            }(window)),

            parseGigyaDate: function(s) { //[confirmed]
                if(!s){
                    return new Date();
                }

                return new Date (
                    s.substring(0,4),
                    parseInt(s.substring(4,6)) -1,
                    s.substring(6,8),
                    s.substring(8,10),
                    s.substring(10,12),
                    s.substring(12)
                );
            }
        };

        NSCR.pgLoadVPWH = NSCR.fn.getViewportSize(); // [confirmed]
        NSCR.pgLoadVPW = NSCR.pgLoadVPWH[0]; // [confirmed]
    })(jQuery, this, this.document);

    /*
     * Gigya socialize plugin Integration for NSCR.
     *
     * NSCR.gigyaService namespace definition
     */
    (function ($, window, document, NSCR, undefined) {
        /**
         * Gigya integration module
         */
        NSCR.gigyaService = (function () {

            NSCR.config.lang = locale.substring(0,2);

            function _gigyaService(){

                var $document = $(document),
                    _this = this,
                    config = {
                        enabledProviders: NSCR.config.enabledSocialProviders.toLowerCase(),
                        autoLogin: false,
                        lang: NSCR.config.lang,
                        newUsersPendingRegistration:false
                    },
                    conf = "{" +
                        "enabledProviders: NSCR.config.enabledSocialProviders.toLowerCase()," +
                        "autoLogin: false," +
                        "lang: NSCR.config.lang," +
                        "connectWithoutLoginBehavior: 'alwaysLogin'," +
                        "isSiteUID: true," +
                        "newUsersPendingRegistration:false"+
                        "};";

                _this.socialUser = null, _this.likeCount = 0, _this.socialSessionObj = null, _this.userFriendList = [], _this.fbLikeCounter = null, _this.lastSocialActionLink = null;

                /**
                 * Init call
                 */
                this.init = function (eParam) {
                    //Load Gigya socialize.js
                    if(!window.gigya){
                        loadGigya();
                    }
                    return _this;
                };

                //Load Gigya socialize.js asynchronously
                var loadGigya = function () { // [confirmed]
                    var s = document.createElement('script'),
                        protocol = location.protocol,
                        gigyaAPI = 'http://cdn.gigya.com/js/socialize.js?apikey=';
                    if(protocol === 'https:'){
                        gigyaAPI = 'https://cdns.gigya.com/js/socialize.js?apikey=';
                    }
                    s.type = 'text/javascript';
                    s.src = gigyaAPI + NSCR.fn.getUrl('gigyaApiKey');
                    s.text = conf;
                    if(typeof(gigyaScript) != 'undefined'){
                        s.src = gigyaScript;
                    }
                    document.getElementsByTagName('head')[0].appendChild(s);
                };

                //Global function to be fired when Gigya's Script has Finished Loading
                window.onGigyaServiceReady = function (serviceName) { // [confirmed]
                    console.log(serviceName + " loaded successfully");

                    //Attach social events on elements dependent on gigya socialize.js
                    initAttachSocialEvent();

                    // Initialize social provider config - the config is now part of global configuration
                    initSocialProviders();

                    //Create FB Like buttons
                    var $FBWrap = NSCR.eventTarget.find('.socialLinks .FBWrap').not('.socialItemCreated');
                    if($FBWrap[0]){
                        $FBWrap.createSocialShareBarItem();
                    }

                    //Init Gigya Chat Plugin
                    $('[data-chat-params]').createLiveChat();

                    if((window.gigya != "undefined")){
                        gigya.accounts.addEventHandlers({
                            onLogin:loginEventHandler,
                            onLogout:logoutEventHandler
                        });
                    }
                };


                // Replacement for the getAvailableProcidersSuccess callback
                var initSocialProviders = function(){ //[confirmed]
                    var providers = config.enabledProviders.split(',');
                    if(providers.length > 0){

                        // Get User Information using Configured Providers
                        _this.getUserInfo({provider: config.enabledProviders});

                        //Load the Javascript files on page if they had dependency on FB or GIGYA.
                        loadDependentJSFiles();

                        if(NSCR.fn.hasProperty(NSCR, "modProfile") === true){
                            NSCR.modProfile.initSocialConnect(providers); // clue point for profile page
                        }

                    }else if(NSCR.fn.hasProperty(NSCR, "modProfile") === true){
                        NSCR.modProfile.initSocialConnect();// clue point for profile page
                    }
                };


                //Logs out the current user of the Gigya platform
                this.socialLogout = function(){
                    if(_this.socialSessionObj !== null){
                        gigya.socialize.logout({
                            callback: function(response){
                                //Execute call back for IDM logout
                                NSCR.nscrCallbacks.executeIdmLogout();
                            }
                        });
                    } else{
                        //Execute call back for IDM logout
                        NSCR.nscrCallbacks.executeIdmLogout();
                    }
                };

                //All Social Links delegation goes here
                var initAttachSocialEvent = function(){ //[confirmed]
                    NSCR.eventTarget.delegate(".socialLinks .share a", "click", function(evt){
                        evt.preventDefault();
                        //Get share items details to be shared on social networks
                        var dataParams = $(this).attr('data-params');
                        if(/^\s*$/.test(dataParams) === false) { initSocialShare(dataParams); } else{ console.log('data-params not defined'); return; }
                    });
                    //Post an NASCAR invitation to Users wall
                    NSCR.eventTarget.delegate('a.crewInviteFriends', 'click', function(evt){
                        evt.preventDefault();
                        var dataParams = $(this).attr('data-params');
                        _this.lastSocialActionLink = $(this);
                        _this.postToSocialNextwork(dataParams, onFriendsInviteSuccess, 'facebook', '#FBMessage');
                    });

                    NSCR.eventTarget.delegate('a.shareCommentOnFB', 'click', function(evt){
                        evt.preventDefault();
                        var dataParams = $(this).attr('data-params'),
                            targetElemnt = $(this).parents('.commentsBlock').find('div.commentSuccess');
                        _this.lastSocialActionLink = $(this);
                        _this.postToSocialNextwork(dataParams, onSuccessPostCommentFB, 'facebook', targetElemnt);
                    });


                    NSCR.eventTarget.delegate('a.shareCommentOnTwitter', 'click', function(evt){
                        evt.preventDefault();
                        var dataParams = $(this).attr('data-params'),
                            targetElemnt = $(this).parents('.commentsBlock').find('div.commentSuccess');
                        _this.postToSocialNextwork(dataParams, onSuccessPostCommentTwitter, 'twitter', targetElemnt);
                    });


                    NSCR.eventTarget.delegate('a.shareCommentOnFBOnPost, a.sharecommentTwitterOnPost', 'click', function(evt){
                        evt.preventDefault();
                        var $this = $(this);
                        if(! $this.hasClass('active')){
                            $this.addClass('active');
                        }
                    });
                };

                this.triggerCallToSocialLinksOnCommentsPost = function(){
                    var title = $('#pageTitle').val(),
                        backLink = $('#backLink').val();
                    if($('#aboutBlog').length > 0){
                        var commentAdded = $('#aboutBlog').val();
                    }else{
                        var commentAdded = $('#socoComments-text').val();
                    }
                    var dataParams = '{"title":" '+ title + '", "backLink" : "' + backLink + '" , "description" : "' + commentAdded + '"}';
                    if($('a.shareCommentOnFBOnPost').hasClass('active')){
                        _this.postToSocialNextwork(dataParams, "", 'facebook', "");
                    } else if($('a.sharecommentTwitterOnPost').hasClass('active')){
                        _this.postToSocialNextwork(dataParams, "", 'twitter', "");
                    }
                };

                var loadDependentJSFiles = function() { //[confirmed]
                    if(NSCR.fn.hasProperty(NSCR, "siteTracking")){
                        NSCR.siteTracking.loadOmniSocialTrackJS();
                    }
                };

                //Call Gigya to Add Social Connection
                this.makeSocialLogin = function(params){ //confirmed
                    var params = $.extend({}, config, params);
                    gigya.socialize.login(params);
                };

                //Call Gigya to Remove Social Connection
                this.makeSocialLogout = function(params){
                    gigya.socialize.removeConnection(params);
                };

                //Get Current User info returns user object
                this.getUserInfo = function(params){ //[confirmed]
                    var params = $.extend({}, config, {
                        callback: getCurrentUserSuccess
                    });
                    //Retrieve extended information regarding the current user
                    gigya.socialize.getUserInfo(params);
                };
                this.isPremiumUser = function(gigyaUserInfo){
                    var isValidFormat = 'undefined' !== typeof gigyaUserInfo && 'undefined' !== typeof gigyaUserInfo.data && 'undefined' !== typeof gigyaUserInfo.data.extendedProfileMapEntitlementsICA;
                    if (!isValidFormat) {
                        return false;
                    }
                    var extendedProfileMapEntitlementsICA = gigyaUserInfo.data.extendedProfileMapEntitlementsICA;
                    var re = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/g;
                    var expArr = re.exec(extendedProfileMapEntitlementsICA);
                    if (!expArr || expArr.length !== 7) {
                        return false;
                    }
                    var expDate = new Date(Number(expArr[1]), Number(expArr[2]), Number(expArr[3]), Number(expArr[4]), Number(expArr[5]), Number(expArr[6]), 0);
                    var nowDate = new Date();
                    return expDate.getTime() > nowDate.getTime();
                };
                //Get Current User Success callback, set user object to global object
                var getCurrentUserSuccess = function(response) { //[confirmed]
                    if(parseInt(response.errorCode, 10) === 0){
                        if(typeof response.user.UID !== 'undefined' && /^\s*$/.test(response.user.UID) === false) {
                            var providerName = response.user.loginProvider;
                            if (_this.socialUser === null) {
                                _this.socialUser = {};
                            }
                            _this.socialUser[providerName] = response.user;
                            //Get Current Facebook Session Info
                            _this.getSessionInfo({provider: providerName});
                            var $myProfileWrap = $("#myProfileWrap");
                            if ($myProfileWrap[0] && NSCR.fn.hasProperty(NSCR, "modProfile") === true) {
                                NSCR.modProfile.getSocialProfilePic(providerName); // seems this is clue point for profile page !!!
                            }
                            if (!!window.appboy) {
                                      appboy.getUser().getUserId(function(userId){
                                        var emailMD5 = MD5(response.user.email);
                                        if( userId != emailMD5){
                                            appboy.changeUser(emailMD5);
                                            appboy.getUser().setEmail(response.user.email);
                                            appboy.getUser().setLastName(response.user.lastName);
                                            appboy.getUser().setFirstName(response.user.firstName);
                                        }
                                        _this.getAccountInfo().done(function (userInfo) {
                                            var isPremiumUser = _this.isPremiumUser(userInfo);
                                            var isFantasyUser = userInfo.data.fantasy_live_lineup_ts ? true : false;
                                            _this.setBrazeCustPrmsAndEvnts(true, !isPremiumUser, isFantasyUser, isPremiumUser);
                                        });
                                    });
                            }
                        }else{
                            if(!! window.appboy){
                                _this.setBrazeCustPrmsAndEvnts(false, false,false, false);
                            }
                        }
                    }
                };

                //Get Session Info form gigya service getSessionInfo
                this.getSessionInfo = function(params){ //[confirmed]
                    var params = $.extend({}, config, {
                        provider: params.provider,
                        context: params.provider,
                        callback: params.callback || getSessionInfoSuccess
                    });
                    gigya.socialize.getSessionInfo(params);
                };

                //Get Session Info success callback
                var getSessionInfoSuccess = function(response){ //[confirmed]
                    if(parseInt(response.errorCode, 10) == 0){
                        //Get Current FB session Object
                        if(_this.socialSessionObj === null){
                            _this.socialSessionObj = {};
                        }
                        _this.socialSessionObj[response.context] = response;

                        /*if(typeof NSCR.gigyaService.socialSessionObj["facebook"] !== "undefined" && response.context === "facebook"){
                         //Get Current User's Friend's List Object
                         initGetFBFriendsList({
                         detailLevel: 'extended',
                         siteUsersOnly: true,
                         callback: getFBFriendListSuccess
                         });

                         //Get FB Like count of current user
                         //FBLikeCount();
                         }*/
                    }
                };

                //Get Current User Like Count
                var FBLikeCount = function(params){
                    if(typeof NSCR.gigyaService.socialSessionObj["facebook"] === "undefined") return;
                    var query = 'SELECT url FROM url_like WHERE user_id = me() and strpos(url, "'+ document.domain +'") > 0';

                    $.ajax({
                        url: "https://graph.facebook.com/fql?q=" + query + "&access_token="+ NSCR.gigyaService.socialSessionObj["facebook"].authToken,
                        method: "get",
                        dataType: "jsonp",
                        success: function(response){
                            if(typeof response.data !== 'undefined'){
                                _this.fbLikeCounter = response.data.length;
                                $('span.FbCount').html(NSCR.gigyaService.fbLikeCounter);
                            }
                        }
                    });
                };

                var getFBFriendListSuccess = function(response){ // [to confirm] seems like it is not used anywhere
                    var errorCode = parseInt(response.errorCode, 10);
                    if(errorCode == 0 && (errorCode != 100 || errorCode != 100001)){
                        _this.userFriendList = response['friends'].asArray();

                        //Update FB events on Event Pages
                        var $eventContentWrap = $('#eventContentWrap');
                        if($eventContentWrap[0]){
                            NSCR.fbEvents.FBInit();
                        }
                    }
                };

                this.postToSocialNextwork = function(dataParams, callback, sProvider, targetObject){ //[confirmed]
                    if(/^\s*$/.test(dataParams) === false) {
                        var actionObj = _this.initSocialActionObject(dataParams);
                        if(actionObj !== null){
                            var params = $.extend({}, config, {
                                userAction: actionObj,
                                callback: callback,
                                enabledProviders: sProvider,
                                context: targetObject
                            });
                            gigya.socialize.publishUserAction(params);
                        }
                    }
                };

                var requestPublishStreamPermissions = function(context, message){ //[confirmed]
                    var params = {
                        provider: 'facebook',
                        permissions: 'publish_stream',
                        callback: function(response){
                            if(parseInt(response.errorCode, 10) == 0){
                                _this.lastSocialActionLink.trigger('click');
                            } else{
                                $(response.context).removeClass('hidden').find('p').html(message);
                                _this.lastSocialActionLink = null;
                            }
                        },
                        context: context
                    };
                    NSCR.gigyaService.requestPermissions(params);
                };

                var onFriendsInviteSuccess = function(response){ //[confirmed]
                    if(parseInt(response.errorCode, 10) == 0){
                        $(response.context).removeClass('hidden').find('p').html(NSCR.glblStringMsgs.fbInviteSuccess);
                    } else if(parseInt(response.errorCode, 10) == 403023){
                        requestPublishStreamPermissions(response.context, NSCR.glblStringMsgs.fbPublishStreamError);
                    } else{
                        $(response.context).removeClass('hidden').find('p').html(NSCR.glblStringMsgs.somethingWentWrong);
                    }
                    window.setTimeout(function(){
                        $(response.context).addClass('hidden');
                    }, 10000);
                };

                var onSuccessPostCommentFB = function(response){ //[confirmed]
                    if(parseInt(response.errorCode, 10) === 0){
                        $(response.context).removeClass('hidden').html(NSCR.glblStringMsgs.fbCommentsPostedSuccess);
                    } else if(parseInt(response.errorCode, 10) == 403023){
                        requestPublishStreamPermissions(response.context, NSCR.glblStringMsgs.fbPublishStreamError);
                    } else{
                        $(response.context).removeClass('hidden').html(NSCR.glblStringMsgs.somethingWentWrong);
                    }
                    window.setTimeout(function(){
                        $(response.context).addClass('hidden');
                    }, 10000);
                };

                var onSuccessPostCommentTwitter = function(response){ //[confirmed]
                    if(parseInt(response.errorCode, 10) == 0){
                        $(response.context).removeClass('hidden').html(NSCR.glblStringMsgs.twitterCommentsPostedSuccess);
                    } else{
                        $(response.context).removeClass('hidden').html(NSCR.glblStringMsgs.somethingWentWrong);
                    }
                    window.setTimeout(function(){
                        $(response.context).addClass('hidden');
                    }, 10000);
                };

                //Returns information about friends of the current user
                /*var initGetFBFriendsList = function(params){
                 var params = $.extend({}, config, params);
                 gigya.socialize.getFriendsInfo(params);
                 };*/

                this.siteUserFBPile = function(faceLen, showNames){ // [to confirm] seems this is not used any more
                    var frndLen = _this.userFriendList.length, friendFacePile = friendProfileLink = '', pileCount = 0;

                    for(var i = 0; i < frndLen; i++){
                        var currFriend = _this.userFriendList[i], nickName = currFriend['nickname'], profileURL = currFriend['profileURL'];
                        //Create facepile image list if current friend is NASCAR.COM user
                        if(currFriend['isSiteUser'] === true){
                            //Create facepile image list
                            if(pileCount < faceLen){
                                friendFacePile += '<li><a href="'+ profileURL +'" title="'+ nickName +'"><img alt="'+ nickName +'" src="'+ currFriend['thumbnailURL'] +'" /></a></li>';
                            }
                            //Create facepile user profile link list
                            if(typeof showNames !== 'undefined' && showNames === true){
                                if(pileCount < 2){
                                    friendProfileLink += '<a href="'+ profileURL +'" title="'+ nickName +'">'+ nickName +'</a>' +' '+ NSCR.glblStringMsgs.strAnd +' ';
                                }
                            }
                            pileCount++;
                        }
                    }
                    return {
                        "pileHTML": friendFacePile,
                        "fbLinkHTML": friendProfileLink,
                        "siteUserLen": pileCount
                    };
                };

                this.requestPermissions = function(params){ //[confirmed]
                    gigya.socialize.requestPermissions(params);
                };

                //Creates a new UserAction instance and set data
                this.initSocialActionObject = function (dataParams) { // [confirmed]
                    try {
                        var dataObj = $.parseJSON(dataParams)
                    } catch (error) {
                        console.log('malformed JSON string Passed');
                        return null;
                    }
                    //Creates a new UserAction instance
                    var actionObj;
                    if (typeof gigya !== 'undefined') {
                        actionObj = new gigya.socialize.UserAction();
                        actionObj.setTitle(dataObj.title); // Setting the Title
                        actionObj.setSubtitle(dataObj.subTitle); // Setting the Subtitle
                        actionObj.setLinkBack(dataObj.backLink); // Setting Link Back
                        actionObj.setDescription(dataObj.description); // Setting Description
                        actionObj.addActionLink(dataObj.actionLinkTxt, dataObj.actionLinkHref); // Adding Action Links
                        actionObj.addMediaItem(dataObj.media); // Add Media Elements to the Post, params will vary for diffrent type of media
                    }

                    return actionObj;
                };

                this.setCurrentUserSweepstakesValue = function (value, callback) {
                    if (arguments.length == 1 || void(0) == callback) {
                        callback = function (o) {
                            if (o.errorCode != 0)
                                alert(o.errorDetails);
                        }
                    }

                    var params = {
                        data: {
                            sweepstakes: value
                        },
                        callback: callback
                    };

                    gigya.accounts.setAccountInfo(params);
                };

                this.setCurrentUserDataValues = function (value, callback) {
                    if (arguments.length == 1 || void(0) == callback) {
                        callback = function (o) {
                            if (o.errorCode != 0)
                                alert(o.errorDetails);
                        }
                    }

                    var params = {
                        data: value,
                        callback: callback
                    };

                    gigya.accounts.setAccountInfo(params);
                };

                //Initialize social share plugin on share link
                var initSocialShare = function (dataParams){ //[confirmed]
                    var actionObj = _this.initSocialActionObject(dataParams),
                        useMode = (NSCR.pgLoadVPWH[0] > NSCR.config.mobileSizes.upperLimit) ? "multiSelect" : "simpleShare";
                    if(actionObj === null){
                        return;
                    }
                    var params = {
                        userAction: actionObj,
                        operationMode: useMode,
                        showMoreButton: false,
                        showEmailButton: false,
                        enabledProviders: "facebook,twitter,yahoo",
                        moreDisabledProviders: "delicious,digg,friendfeed,messenger,myaol,stumbleupon,orkut,skyrock,qq,sina,kaixin,renren,vznet,vkontakte,spiceworks,viadeo,nkpl,xing,tuenti,technorati,plaxo,reddit,formspring,tumblr,faves,newsvine,fark,mixx,bitly,misterwong,ask,amazon,gmail,baidu,box,netlog,evernote,aolmail,currenttv,yardbarker,blinklist,diigo,backflip,dropjack,segnalo,linkagogo,kaboodle,skimbit,hyves,googleplus,linkedin,pinterest,mixi,myspace,boxnet,hatena,odnoklassniki,douban,googlebookmarks"
                    };

                    gigya.socialize.showShareUI(params);
                };
                this.setBrazeCustPrmsAndEvnts = function(isLoggedIn, isFreeUser, isFantasyUser, isPaidUser){
                    appboy.getUser().setCustomUserAttribute(
                        'Web_Is_logged_in',
                        isLoggedIn
                    );
                    appboy.getUser().setCustomUserAttribute(
                        'Web_Is_Fantasy_User',
                        isFantasyUser
                    );
                    appboy.getUser().setCustomUserAttribute(
                        'Web_Is_free_user',
                        isFreeUser
                    );

                    appboy.getUser().setCustomUserAttribute(
                        'Web_Is_paid_user',
                        isPaidUser
                    );
                    if(pageType == 'post'){
                        logAppBoyEvent("Read an article");
                    }
                    if(pageType == 'ndms_vidoes'){
                        logAppBoyEvent("Watched a video");
                    }
                    if(pageType == 'racecenter'){
                        logAppBoyEvent("Engaged with Race Center");
                    }
                };
                this.getAccountInfo = function(){
                    var d = new jQuery.Deferred(), t;
                    t = setTimeout(function(){d.resolve();}, 30*1000);
                    if(window.gigya) {
                        gigya.accounts.getAccountInfo({
                            callback: function (r) {
                                clearTimeout(t);
                                d.resolve({
                                    profile: r['profile'],
                                    data: r['data'],
                                    uid: r['UID'],
                                    sig: r['UIDSignature'],
                                    ts: r['signatureTimestamp']
                                });
                            }
                        });
                    }

                    return d.promise();
                };

                return this.init();
            }

            return new _gigyaService();
        }());

    }(jQuery, this, this.document, NSCR));

    /**
     * @name: createSocialShareBarItem
     * @author: Vinod
     * @description: plug-in to add FBLike and Other social buttons in target elements
     */
    (function($){
        $.fn.createSocialShareBarItem = function (config){ //[confirmed]
            var defaults = {
                dataParamsAttr: 'data-params',
                dataWidgetAttr: 'data-widget'
            };

            if(this.length === 0) {
                return this;
            }

            return this.each(function () {
                if($(this).children()[0]){
                    return;
                }

                var _this = $(this), dataParams = _this.attr(defaults.dataParamsAttr), buttonType = _this.attr(defaults.dataWidgetAttr).split('-');

                //create a unique Id for each widget container (required for gigya.socialize.showShareBarUI)
                _this.attr('id',  buttonType[0] +  NSCR.gigyaService.likeCount++);

                if(/^\s*$/.test(dataParams) === false){
                    var actionObj = NSCR.gigyaService.initSocialActionObject(dataParams);
                    if(typeof actionObj !== 'object' || $.isEmptyObject(actionObj)){
                        return;
                    }
                } else {
                    console.log('data-params not defined');
                    return;
                }

                var params = $.extend(true, {
                    shareButtons: _this.attr(defaults.dataWidgetAttr),
                    userAction: actionObj,
                    containerID: _this.attr('id')
                }, config || {});

                _this.addClass("socialItemCreated");

                gigya.socialize.showShareBarUI(params);

            });
        };
    })(jQuery);

    /**
     * @name: createLiveChat
     * @author: Rohit
     * @description: plug-in to create Live Chat
     */
    (function($){
        $.fn.createLiveChat = function (config) { //[confirmed]
            var defaults = {
                    dataParamsAttr: 'data-chat-params'
                },
                _this = {};

            if(this.length === 0){
                return this;
            }

            var initLiveChats = function(dataParamsObj){
                var wrapId =  _this.attr('id'),
                    chatWrapW = _this.css('width', 'auto').width() === '0' ? '100%' : _this.css('width', 'auto').width(),
                    chatWrapH = _this.height(),
                    params = {
                        containerID: wrapId, // The component will embed itself inside the divConnect Div
                        categoryID: dataParamsObj.categoryID, // Insert here the categoryID obtained from the chat setup
                        width: chatWrapW,
                        height: chatWrapH,
                        twitterQuery: dataParamsObj.twitterQuery,
                        cid: dataParamsObj.cid //context id to tag data
                    };
                gigya.socialize.showChatUI(params);

                var chatLoadInterval = setInterval( function(){
                    if(!$("#liveChatContainer-lnkLogout")[0]) return;
                    clearInterval(chatLoadInterval);

                    var originalLink = $("#liveChatContainer-lnkLogout"),
                        newLink = originalLink.clone(false);
                    originalLink.replaceWith(newLink);

                    NSCR.eventTarget.delegate("#liveChatContainer-lnkLogout", "click", function(evt){
                        evt.preventDefault();
                        gigya.socialize.logout();
                    });
                }, 3000);
            };

            var convertParamsToObj = function(dataParams){
                try {
                    return dataObj = $.parseJSON(dataParams);
                } catch (error) {
                    return null;
                }
            };

            return this.each(function () {
                _this = $(this);

                var dataParams = _this.attr(defaults.dataParamsAttr),
                    dataParamsObj = convertParamsToObj(dataParams);

                if(dataParamsObj !== null){
                    initLiveChats(dataParamsObj);
                }
            });
        };
    })(jQuery);
    function setHiddenGigyaFields(cb){
        jQuery(".chkPartnerOffers").attr('checked', cb.checked);
        jQuery(".chkEventsAndProducts").attr('checked', cb.checked);
    }

    /**
     * NSCR.siteTracking namespace definition
     */
    (function ($, window, document, undefined) {

        NSCR.siteTracking = (function () {//[confirmed]

            function _siteTracking() {
                var idmUserType = null,
                    context = this;

                this.trackingPageName = '';

                this.init = function() {
                    idmUserType = NSCR.login.idmUserType;
                    if(typeof NSCR.config.trackingState !== 'undefined' && NSCR.config.trackingState === true){
                        initAttachTrackingEvents();
                    }
                    initPageLoadTracking();
                    sendOnLoadBTInfo();
                };

                this.idmUserSuccessTracking = function(trackingObj){ // [to confirm] seems like it is not using anymore
                    if(typeof NSCR.config.cookie.userSuccess !== 'undefined'){
                        var utCookie = NSCR.config.cookie.userSuccess,
                            pageName = s.pageName || '';
                        pageName = pageName.replace(/;,/g, "");
                        NSCR.fn.createCookie(utCookie.name, JSON.stringify($.extend(trackingObj, {"sourcePageName": pageName})), utCookie.expire, utCookie.path, utCookie.domain);
                    }
                };

                var initPageLoadTracking = function(){ //[confirmed]
                    //Set Fan Type form personalization cookie
                    var $trackDeviceType = $('#trackDeviceType'),
                        $trackLoginState = $('#trackLoginState'),
                        $trackFanType = $('#trackFanType'),
                        thisPageName = $('#thisPageName').attr('data-tracking-page-name') || null,
                        personalizeCookie = null,
                        fanType = 'nascarUserSegment:=',
                        fanVal = 'Casual',
                        $myProfileWrap = $("#myProfileWrap");

                    if(typeof NSCR.config.cookie.personalization !== 'undefined'){
                        var personalizeCookie = NSCR.fn.readCookie(NSCR.config.cookie.personalization.name);
                        //Fan type of user
                        if(personalizeCookie !== null){
                            personalizeCookie = decodeURIComponent(personalizeCookie);
                            var fanCookieIdx = personalizeCookie.indexOf(fanType);
                            if(fanCookieIdx !== -1){
                                var fanText = personalizeCookie.substr(fanCookieIdx + fanType.length);
                                fanVal = $.trim(fanText.split('|')[0]);
                            }
                        }
                    }

                    //Set Users Logged-in/Logged-out status
                    var loggedIn = 'LoggedOut';

                    if(typeof gigyaScript !== "undefined"){
                      var u_i = NSCR.fn.readCookie(NSCR.config.cookie.gigUID.name);
                      if((typeof u_i !="undefined") && u_i != '' && u_i != null){
                        NSCR.login.idmUserID = u_i;
                      }
                    }

                    if(NSCR.login.idmUserID !== null && NSCR.login.idmUserID !== ""){
                        loggedIn = 'LoggedIn';
                    }
                    if(loggedIn !== 'LoggedOut'){
                      // [to confirm] this one definitely not used
                        // var trackLoginStateObj = getPageLoadRecordJSON($trackLoginState);
                        // if(trackLoginStateObj !== null){
                        //     trackLoginStateObj.userAuthStatus = loggedIn;
                        //     trackLoginStateObj.userID = NSCR.login.idmUserID;
                        //     trackLoginStateObj.fanType = fanVal;
                        //     setPageLoadRecordJSON($trackLoginState, trackLoginStateObj);
                        // }

                        /*setting properties on digitalData object*/
                        NSCR.login.favDriverID = NSCR.fn.readCookie(NSCR.config.cookie.favDriverID.name);
                        NSCR.login.favDriver = NSCR.fn.readCookie(NSCR.config.cookie.favDriver.name);
                        var userRegSource = NSCR.fn.readCookie(NSCR.config.cookie.userRegSource.name);
                        var userRegDate = NSCR.fn.readCookie(NSCR.config.cookie.regDate.name);
                        var usrLstLgnDt = NSCR.fn.readCookie(NSCR.config.cookie.lastLoginDate.name);
                        var usrICAEnt = NSCR.fn.readCookie(NSCR.config.cookie.entitlementsICA.name);
                        var usrRVPEnt = NSCR.fn.readCookie(NSCR.config.cookie.entitlementsRVP.name);

                        if(!userRegSource){
                            userRegSource='';
                        }

                        if(!usrLstLgnDt){
                            usrLstLgnDt='';
                        }
                        if(!userRegDate){
                            userRegDate='';
                        }
                        if(!usrICAEnt){
                            usrICAEnt='';
                        }
                        if(!usrRVPEnt){
                            usrRVPEnt='';
                        }
                        if (digitalData){
                            digitalData.page.userInfo = {
                              'userID' : NSCR.login.idmUserID,
                              'favoriteDriver': NSCR.login.favDriver,
                              'regSource':userRegSource,
                              'regDate':userRegDate,
                              'lastLoginDate':usrLstLgnDt,
                              'entitlementsICA':usrICAEnt,
                              'entitlementsRVP':usrRVPEnt
                            }
                        }
                    }

                    //Set User's Device Type
                    var contentWidth = $('.moduleContent').outerWidth(),
                        deviceType = 'Desktop';
                    if(Modernizr.touch){
                        deviceType = (contentWidth <= NSCR.config.mobileSizes.upperLimit) ? 'MobilePhone' : 'Tablet';
                    }
                    if(deviceType !== 'Desktop'){
                        var trackDeviceTypeObj = getPageLoadRecordJSON($trackDeviceType);
                        if(trackDeviceTypeObj){
                            trackDeviceTypeObj.deviceType = deviceType;
                            setPageLoadRecordJSON($trackDeviceType, trackDeviceTypeObj);

                            /*Also setting properties on digitalData object for NM-5430 */
                            if (digitalData){
                                digitalData.page.attributes.deviceType = deviceType;
                            }
                        }
                    }

                    /*Code Fix 1.8: 795:*/
                    if(/^\s*$/.test(thisPageName) === false){
                        context.trackingPageName = thisPageName;
                    }
                    entitlementTracking();
                };

                //NM-4588 - if we have global omniture and entitlements
                var entitlementTracking = function(){ // [confirmed]
                    NSCR.gigyaService.getAccountInfo().done(function(userInfo){
                        var value = [];
                        //We do the work that NSCR.userEntitleAndPref.entitlement does because it isn't init'ed at this point
                        //but we do have the info in the cookie.
                        var d = getEntitleAndPrefFromCookie(NSCR.config.cookie.entitlements,"products:=");
                        //Read the products the user has
                        if(d !== null){
                            if(d.rvp !== undefined){
                                value.push("Entitlement: RaceView");
                                //value.push("Entitlement: Scanner");
                            }
                            //Don't want to duplicate the scanner entitlement.
                            if(d.rvp === undefined && d.ica !== undefined){
                                value.push("Entitlement: Scanner");
                            }
                        }

                        //This reads the property of the u_i cookie that attempts
                        if(userInfo && userInfo.data && userInfo.data.fantasy_action_live !== undefined){
                            value.push("Entitlement: Fantasy");
                        }

                        //multiple entitlements found OBSELETE - handled by ensighten
                        //if(value.length > 0){
                        //	value.push("event76");
                        //}
                        window.ensightenEntitlementProp = value.join(',');
                    });
                };
                //end NM-4588

                var subscriptionTracking = function(trackTypeObj){ // [to confirm] this one definitely not used
                    if(typeof NSCR.userEntitleAndPref.subscription !== "undefined"){
                        var sKey = "";
                        for(var key in NSCR.userEntitleAndPref.subscription){
                            key = key.split('question')[1] || key;
                            sKey = key.toLowerCase();
                            if(sKey.indexOf("promotions") !== -1 || sKey.indexOf("newsletter") !== -1){
                                trackTypeObj.var20 = (typeof trackTypeObj.var20 !== "undefined") ? trackTypeObj.var20 + "," + key : key;
                            }
                            if(sKey.indexOf("insurance") !== -1 || sKey.indexOf("offer") !== -1){
                                trackTypeObj.var21 = (typeof trackTypeObj.var21 !== "undefined") ? trackTypeObj.var21 + "," + key : key;
                            }
                        }
                        s.events = (typeof s.events !== "undefined") ? s.events + "," + "event10" : "event10";
                    }
                    return trackTypeObj;
                };

                var getPageLoadRecordJSON = function($targetElement){ // [confirmed]
                    var recordStr = $targetElement.attr('record');

                    if(recordStr){
                        return convertParamsToObj(recordStr.substr(recordStr.indexOf('{')));
                    }
                };

                var setPageLoadRecordJSON = function($targetElement, jsonObj){ // [confirmed]
                    var recordStr = $targetElement.attr('record'),
                        recordStrPart = recordStr.substr(0, recordStr.indexOf('{'));

                    $targetElement.attr('record', recordStrPart + JSON.stringify(jsonObj));
                };

                var initAttachTrackingEvents = function(){ // [confirmed]

                    NSCR.eventTarget.delegate('[data-add-comment-bt]', 'click', function(){
                        if(NSCR.login.idmUserID !== null && NSCR.login.idmUserID !== ""){
                            var btTrackingParams = $(this).attr('data-add-comment-bt'),
                                btTrackingObj = convertParamsToObj(btTrackingParams);

                            if(btTrackingObj !== null){
                                btTrackingObj.userID = NSCR.login.idmUserID;
                                if(typeof tagBT !== 'undefined'){
                                    tagBT(btTrackingObj);
                                }
                            }
                        }
                    });

                    NSCR.eventTarget.delegate('[data-remove-comment-bt]', 'click', function(){
                        if(NSCR.login.idmUserID !== null && NSCR.login.idmUserID !== ""){
                            var btTrackingParams = $(this).attr('data-remove-comment-bt');

                            if(btTrackingParams !== 'undefined'){
                                btTrackingParams = btTrackingParams.replace('+', '-');
                            }

                            var btTrackingObj = convertParamsToObj(btTrackingParams);
                            if(btTrackingObj !== null){
                                btTrackingObj.userID = NSCR.login.idmUserID;
                                if(typeof tagBT !== 'undefined'){
                                    tagBT(btTrackingObj);
                                }
                            }
                        }
                    });
                };

                this.sendOmnitureTrackingOnClick = function($targetElement){ // [to confirm] it is doing nothing
                };

                this.sendFavBtTrackingInfo = function($targetElement, actionType){ // [to confirm] it is doing nothing if tagBT === 'undefined'
                    if(NSCR.login.idmUserID !== null && NSCR.login.idmUserID !== ""){
                        var btTrackingParams = $targetElement.attr('data-fav-bt');

                        if(typeof actionType !== 'undefined' && typeof btTrackingParams !== 'undefined' && $.trim(btTrackingParams) !== ''){
                            btTrackingParams = btTrackingParams.replace('+', '-');
                        }

                        var btTrackingObj = convertParamsToObj(btTrackingParams);
                        if(btTrackingObj !== null){
                            btTrackingObj.userID = NSCR.login.idmUserID;
                            if(typeof tagBT !== 'undefined'){
                                NSCR.btTrackingFlag = true;
                                tagBT(btTrackingObj);
                            }
                        }
                    }
                };

                this.loadOmniSocialTrackJS = function() { //[confirmed]
                    Modernizr.load([{
                        load: NSCR.fn.getUrl("omniSocialTrackingJS"),
                        complete: function() {
                            // Write Your code in case you have to execute some logic after loading of "omniSocialTrackingJS" file.
                        }
                    }]);
                };

                var sendOnLoadBTInfo = function(){ // [confirmed]
                    if(NSCR.login.idmUserID !== null && NSCR.login.idmUserID !== ""){
                        var btTrackingParams = $('#btPageLoad').attr('data-onload-bt'),
                            btTrackingObj = convertParamsToObj(btTrackingParams);

                        if(btTrackingObj !== null){
                            btTrackingObj.userID = NSCR.login.idmUserID;
                            if(typeof tagBT !== 'undefined'){
                                tagBT(btTrackingObj);
                            }
                        }
                    }
                };

                var convertParamsToObj = function(dataParams){ // [confirmed]
                    try {
                        return dataObj = $.parseJSON(dataParams);
                    } catch (error) {
                        return null;
                    }
                };

                return this;
                return this;
            };

            return new _siteTracking();

        }());

    })(jQuery, this, this.document);

    jQuery(function(){
        NSCR.siteTracking.init();
    });

    (function (jQuery, window, document, undefined) {
        if(typeof gigyaScript !== "undefined"){
          jQuery(window).on('load', function(){

                var screenSet = "";

                if(NSCR.pgLoadVPW < NSCR.config.mobileSizes.upperLimit){

                    //screenSet = "Mobile-login-" + locale;
                    screenSet = NSCR.config.gigya.gigyaMobileRegistrationScreen;
                    jQuery(".gigyaRegisterDialog").attr("href", "javascript:").attr("onclick", "gigya.accounts.showScreenSet({screenSet:'"+screenSet+"', startScreen:'gigya-register-screen', onAfterScreenLoad: makeMobileScreenScrollable, onHide: showPageWrapper});");
                    jQuery(".gigyaRegisterDialogLower").attr("href", "javascript:").attr("onclick", "gigya.accounts.showScreenSet({screenSet:'"+screenSet+"', startScreen:'gigya-register-screen', onAfterScreenLoad: makeMobileScreenScrollable, onHide: showPageWrapper});");
                    jQuery(".gigyaLoginDialog").attr("href", "javascript:").attr("onclick", "gigya.accounts.showScreenSet({screenSet:'"+screenSet+"', onAfterScreenLoad: makeMobileScreenScrollable, onHide: showPageWrapper});");

                }else{

                    //screenSet = "Login-web-" + locale;
                    screenSet = NSCR.config.gigya.gigyaRegistrationScreen;
                    jQuery(".gigyaRegisterDialog").attr("href", "javascript:").attr("onclick", "gigya.accounts.showScreenSet({screenSet:'"+screenSet+"', startScreen:'gigya-register-screen'});");
                    jQuery(".gigyaRegisterDialogLower").attr("href", "javascript:").attr("onclick", "gigya.accounts.showScreenSet({screenSet:'"+screenSet+"', startScreen:'gigya-register-screen'});");
                    jQuery(".gigyaLoginDialog").attr("href", "javascript:").attr("onclick", "gigya.accounts.showScreenSet({screenSet:'"+screenSet+"'});");

                }

                if(getURLParameter("loginPopUp") == "true"){
                  if( jQuery(".gigyaLoginDialog").length ) {
                    jQuery(".gigyaLoginDialog").click();

                  } else { // runs Login when button is not configured in Navigation

                    var customLangParams={
                        login_identifier_exists: 'Please Enter A Valid Email',
                        unique_identifier_exists: 'Please Enter A Valid Email',
                        email_already_exists: 'Please Enter A Valid Email'
                    };
                    if(NSCR.pgLoadVPW < NSCR.config.mobileSizes.upperLimit){

                        screenSet = NSCR.config.gigya.gigyaMobileRegistrationScreen;
                        gigya.accounts.showScreenSet({screenSet:screenSet, onAfterScreenLoad: makeMobileScreenScrollable, onHide: showPageWrapper,customLang: customLangParams});

                    }else{
                        screenSet = NSCR.config.gigya.gigyaRegistrationScreen;
                        gigya.accounts.showScreenSet({screenSet: screenSet, onAfterScreenLoad: desktopAfterScreenLoad,customLang: customLangParams});

                    }
                  }

                  deleteProfileInfo(false);
                }

                if(getURLParameter("loadScreen") && getURLParameter("loadScreen").length > 0){
                    loadGigyaScreen(screenSet,getURLParameter("loadScreen"));
                }

                handleUserState();
            });
        }
    })(jQuery, this, this.document);

    function onSubmitButtonClicked() { // [confirmed]

      //grab
      var driverSelected = jQuery('#favouriteDriverName').find(":selected").text();
      jQuery("#favouriteDriver").val(driverSelected);

        var email = jQuery("input.gigya-valid[name='email']").first().val();

        function enableSubmitButton(enable) {
            var button = jQuery("div#gigya-register-screen input.gigya-input-submit[type=button]").first();

            if (enable) {
                button.css('opacity', '1').css('pointer-events', 'auto');
            } else {
                button.css('opacity', '.5').css('pointer-events', 'none');
            }
        }

        if (email) {
            enableSubmitButton(false);

            jQuery.ajax({
                url: "https://bpi.briteverify.com/emails.json?address=" + email + "&apikey=406fecd6-e15d-4f0a-bc26-9531877a24f7",
                dataType: "jsonp",
                timeout: 15000,
                success: function (data) {
                    var status = data.status.toLowerCase();

                    enableSubmitButton(true);

                    if (status === 'valid' || status === 'accept_all' || status === 'unknown') {
                        jQuery("div#gigya-register-screen form.gigya-register-form input[type=submit]")
                            .first().click();
                    } else {
                        jQuery("div#gigya-register-screen span.gigya-error-msg[data-bound-to='email']")
                            .first()
                            .addClass("gigya-error-msg-active")
                            .addClass("gigya-error-code-400006")
                            .html("E-mail address is invalid.");
                    }
                },
                error: function (x, t, m) {
                    enableSubmitButton(true);

                    if (t === "timeout") {
                        jQuery("div#gigya-register-screen span.gigya-error-msg[data-bound-to='email']")
                            .first()
                            .addClass("gigya-error-msg-active")
                            .html("Can't validate e-mail address, please try again later");
                    }
                }
            });
        }


    }

    // Adds ability to pre-select subscription based on country code
    function newsletterSignup(){ // [confirmed]
        var doCheck = false;
        var country = document.getElementById('country');
        var newsletter = document.getElementById('newsLetterSub');
        if(country && newsletter){
            if(country.options[country.selectedIndex].value === "USA"){
                doCheck = true;
            }
            newsletter.checked = doCheck;
        }
    }

    function showPageWrapper(){
        var body = jQuery('body');
        if(location.hash == ''){
            jQuery('#pageWrapper').css('display', 'block');
            body.removeAttr("onhashchange");
        }
    }

    function makeMobileScreenScrollable() { // [confirmed]
        //New Code added for ticket CD-1921
        driverListDropDownOptions()

        jQuery("#pageWrapper").css("display", "none");
        var body = jQuery('body');
        try{
            jQuery.unnonbounce(); // enables native iphone elastic scrollbar.
        }catch(err) {
            console.log("openMobile error:"+err);
        }
        jQuery('.gigya-screen-dialog').bind('touchmove',function(e) {
            e.preventDefault();
        });
        jQuery('.navheader').bind('touchmove',function(e) {
            e.preventDefault();
        });
        body.attr("onhashchange", "showPageWrapper();");

    }

    //This function will be called after the screen loads
    function desktopAfterScreenLoad(){
        //New Code added for ticket CD-1921
        driverListDropDownOptions();
    }

    function callService(url, callbackName, queryParams) { // [confirmed]
        return jQuery.ajax({
            type: "GET",
            url: url + "?" + queryParams,
            beforeSend: function(xhr){
                xhr.withCredentials = true;
            },
            dataType: "json",
            async: false,
            timeout: 5000,
            cache: false,
            contentType: "application/json",
            success: function(){
                console.log('Success');
            },
            error: function(xhr, exception) {
                //TO DO :: Create a cookie to tell the service failed
                //console.log(exception);
            }
        });
    }

    function setUserRegSource(userInfo){
        var userRegSource = NSCR.config.cookie.userRegSource;
        if(typeof userInfo.regSource != 'undefined'){
            if(!NSCR.fn.readCookie(userRegSource.name)) {
                NSCR.fn.createCookie(userRegSource.name, userInfo.regSource, 30, userRegSource.path, userRegSource.domain);
            }
            if(!NSCR.fn.readCookie(NSCR.config.cookie.lastLoginDate.name)) {
                NSCR.fn.createCookie(NSCR.config.cookie.lastLoginDate.name, userInfo.lastLogin, 30, NSCR.config.cookie.lastLoginDate.path, NSCR.config.cookie.lastLoginDate.domain);
            }
            if(!NSCR.fn.readCookie(NSCR.config.cookie.regDate.name)) {
                NSCR.fn.createCookie(NSCR.config.cookie.regDate.name, userInfo.registered, 30, NSCR.config.cookie.regDate.path, NSCR.config.cookie.regDate.domain);
            }
        }else{
            gigya.accounts.getAccountInfo({callback: setUserRegSource, include: 'profile,data,subscriptions,regSource'});
        }
        // NSCR.fn.createCookie(authenticatedUser.name, JSON.stringify(userInfo), 30, authenticatedUser.path, authenticatedUser.domain);
        if(userInfo.data.extendedProfileMapEntitlementsRVP) {
            NSCR.fn.createCookie(NSCR.config.cookie.entitlementsRVP.name, userInfo.data.extendedProfileMapEntitlementsRVP, 30 , NSCR.config.cookie.entitlementsRVP.path, NSCR.config.cookie.entitlementsRVP.domain);
        }
        if(userInfo.data.extendedProfileMapEntitlementsICA) {
            NSCR.fn.createCookie(NSCR.config.cookie.entitlementsICA.name, userInfo.data.extendedProfileMapEntitlementsICA, 30, NSCR.config.cookie.entitlementsICA.path, NSCR.config.cookie.entitlementsICA.domain);
        }
    }

    function setUserSubscription(userInfo){ // [confirmed]
        if(typeof userInfo.data === "undefined"){
            gigya.accounts.getAccountInfo({callback: setUserSubscription});
        }
        else{
            var userSubscription = NSCR.config.cookie.subscriptions;
            var subscriptions = "";
            if(userInfo.data.newsLetterSub == true){
                subscriptions += "promotions,";
            }
            if(userInfo.data.eventsAndProductsSub == true){
                subscriptions += "insurance,";
            }
            if(userInfo.data.partnerOffers== true){
                subscriptions += "partneroffers,";
            }
            if(subscriptions != ""){
                NSCR.fn.createCookie(userSubscription.name, "subscriptions:=" + subscriptions, 30, userSubscription.path, userSubscription.domain);
            }
        }
    }

    function getHost(redirectTo) {// [confirmed]
        var hostname;
        if (redirectTo.indexOf("//") > -1) {
            hostname = redirectTo.split('/')[2];
        }
        else {
            hostname = redirectTo.split('/')[0];
        }
        hostname = hostname.split(':')[0];
        hostname = hostname.split('?')[0];
        return hostname;
    }

    function getRoot(redirectTo) {// [confirmed]
        var domain = getHost(redirectTo),
            splitArr = domain.split('.'),
            arrLen = splitArr.length;
        if (arrLen > 2) {
            domain = splitArr[arrLen - 2] + '.' + splitArr[arrLen - 1];
            if (splitArr[arrLen - 2].length == 2 && splitArr[arrLen - 1].length == 2) {
                domain = splitArr[arrLen - 3] + '.' + domain;
            }
        }
        return domain;
    }

    function retrieveProfileInfo(response){ // [confirmed]
        try{
            if (response.UID != "") {
                var userInfo = {
                    profile: response['profile'],
                    data: response['data'],
                    uid: response['UID'],
                    sig: response['UIDSignature'],
                    ts: response['signatureTimestamp']
                };
                setUserSubscription(response);
                // var authenticatedUser = NSCR.config.cookie.authenticatedUser;
                var gigUID = NSCR.config.cookie.gigUID;
                var hashValue = NSCR.config.cookie.hashValue;
                NSCR.fn.createCookie(gigUID.name, userInfo.uid, 30, gigUID.path, gigUID.domain);

                var favDriver = NSCR.config.cookie.favDriver;
                NSCR.fn.createCookie(favDriver.name, userInfo.data.myListsAthlete, 30, favDriver.path, favDriver.domain);

                var favDriverID = NSCR.config.cookie.favDriverID;
                NSCR.fn.createCookie(favDriverID.name, userInfo.data.myListsAthleteIds, 30, favDriverID.path, favDriverID.domain);
                var userEmail='';
                if(typeof jsSHA !== 'undefined'){
                    userEmail=(userInfo['profile'] != null)? userInfo['profile'].email : '';
                    var shaObj = new jsSHA("SHA-256", "TEXT"),userEmail;
                    shaObj.update(userEmail);
                    userEmail = shaObj.getHash("HEX");
                    userEmail = userEmail.toUpperCase();
                }
                NSCR.fn.createCookie(hashValue.name, userEmail, 30, hashValue.path, hashValue.domain);
            }
            else {
                console.log('Error creating the cookies');
            }
        }catch(exp){
            console.log('Error :' + exp);
        }

        var redirectTo = getURLParameter("redirectTo");

        var tempDomain = '';
        if(NSCR.pgLoadVPW < NSCR.config.mobileSizes.upperLimit){
            //Mobile Devices to allow Welcome Screen Display
            jQuery(".gigya-screen-dialog-close").on("click", reloadCurrentPage);//refresh page when close button clicked
            if(typeof redirectTo != "undefined" && redirectTo != "" && !response['newUser']){
                tempDomain = getRoot(redirectTo);
                  if((tempDomain == 'nascar.com') || (tempDomain == 'fanschoice.tv')){
                  window.location.href = redirectTo;
                }else{
                  window.location.href = 'https://www.nascar.com';
                }
            }else{
                if (typeof loginFromCommentsSection != "undefined" && loginFromCommentsSection) { // this is clue point to liferayComments
                    setTimeout(function(){
                        location.reload();
                    }, 2000);
                } else if (!response['newUser']) {
                    location.reload();
                }
            }
        } else {

            if(typeof redirectTo != "undefined" && redirectTo != ""){
                tempDomain = getRoot(redirectTo);
                if((tempDomain == 'nascar.com') || (tempDomain == 'fanschoice.tv')){
                  window.location.href = redirectTo;
                }else{
                  window.location.href = 'https://www.nascar.com';
                }
            }else{
                if (typeof loginFromCommentsSection != "undefined" && loginFromCommentsSection) { // this is clue point to liferayComments
                    setTimeout(function(){
                        location.reload();
                    }, 2000);
                } else {
                    location.reload();
                }
            }
        }

        //SET OPEN-REDIRECT CONDITION(S)
        // if( window.location.href.indexOf("https://nascar.com" || "http://nascar.stage-editor.ndms.nascar.com") != -1 ) {
        //
        //   window.location.href = "https://nascar.com";
        //   console.log(window.location.href);
        //
        // }else if  ( window.location.pathname != "https://www.nascar.com/myprofile" ){
        //
        //   window.location.pathname = "https://www.nascar.com";
        //   console.log(window.location.pathname);
        //
        // }
        // else {
        //   //Do nothing
        // }
        //END SET OPEN-REDIRECT CONDITION(S)


    }

    function reloadCurrentPage() { // [confirmed]
        location.reload();
    }


    function nascarSailThruProfileSync(userData,sailthruGigyaSyncCallbackURL){
        jQuery.ajax({
            type: "POST",
            url:  sailthruGigyaSyncCallbackURL,
            success: function (msg) {
                if (msg) {
                    console.log('Sync Successfull');
                }
            },
            data: "userData=" + JSON.stringify(userData)
        });
    }

    function loginEventHandler(loginResponse) {
        /*SailThru*/
        if((window.gigya != "undefined") && loginResponse.newUser){
          var callback_url = window.SailthruGigyaSyncCallbackURL?window.SailthruGigyaSyncCallbackURL:'https://www.nascar.com/wp-content/themes/ndms/inc/sailthru-gigya-integration/sailthru-gigya-integration.php';
          nascarSailThruProfileSync(loginResponse,callback_url);
        }
        setUserRegSource(loginResponse);
        setTimeout(function(){ performLogin(loginResponse); }, 1000);
     }

    function performLogin(loginResponse){

        var queryParams = {
            uid: loginResponse.UID,
            uid_signature: encodeURIComponent(loginResponse.UIDSignature),
            uid_timestamp: loginResponse.signatureTimestamp,
            display_name: (loginResponse.profile.firstName + " " + loginResponse.profile.lastName).trim(),
            image_url: loginResponse.profile.photoURL
        };

        queryParams = jQuery.param(queryParams);
        console.log(queryParams);

        callService(NSCR.config.url.gigyaLiveFyreEndPoint, "createLiveFyreToken", queryParams);
        callService(NSCR.config.url.gigyaEntitlementsEndPoint, "createEntitlements", queryParams).then(function(data){
            createEntitlementsCookieIfNeeded(data);
        });
        if(typeof loginFromCommentsSection != "undefined" && loginFromCommentsSection){ // this is clue point to liferayComments
            doLivefyreAuth();
        }
        var loginStatus = NSCR.config.cookie.getLoginStatus;
        loginStatus.domain = '.'+getRoot(window.location.host);
        NSCR.fn.createCookie(NSCR.config.cookie.loginStatus.name, true, 30, loginStatus.path, loginStatus.domain);
        retrieveProfileInfo(loginResponse);
    }

    function createEntitlementsCookieIfNeeded(data){
        var entitlements = NSCR.fn.readCookie(NSCR.config.cookie.entitlements.name);
        //NSCR.fn.deleteCookie(NSCR.config.cookie.entitlements.name, NSCR.config.cookie.entitlements.domain);
        if(!entitlements){
            var entType, entDate, entList = [],expiry, value;

            try{
                var customData = data.response.data
            }catch(e) {}
            if (customData){
                // Cycle through the user's entitlements
                for(var key in customData){
                    if(key.indexOf('extendedProfileMapEntitlements') > -1){
                        entType = key.slice(-3).toLowerCase();

                        // Ensure that this field is one of the allowed types
                        if(['rvp','ica','isp'].indexOf(entType) > -1){
                            entDate = NSCR.fn.parseGigyaDate(customData[key]);

                            if(entDate.getTime() >= new Date().getTime()){
                                entList.push(entType);
                                expiry = entDate;
                            }
                        }
                    }
                }

                var dateformat = function(d){
                    //2020-03-06 06:00:00 GMT
                    return "" +
                        d.getFullYear() + "-" +
                        (d.getMonth()+1  <= 9 ? "0" : "") + (d.getMonth()+1)  + "-" +
                        (d.getDate() <= 9 ? "0" : "" ) + d.getDate()  + " " +
                        (d.getHours() <=9 ? "0" : "") + d.getHours() + ":" +
                        (d.getMinutes() <=9 ? "0" : "") + d.getMinutes() + ":" +
                        (d.getSeconds() <=9 ? "0" : "") + d.getSeconds() + " GMT";
                } ;

                value = "sig:=|" +
                "|products:=" + (entList&&entList.length ? entList.toString() : "") +
                "|expiry:=" + (expiry ? dateformat(expiry) : "");

                NSCR.fn.createCookie(
                    NSCR.config.cookie.entitlements.name,
                    value,
                    NSCR.config.cookie.entitlements.expire,
                    NSCR.config.cookie.entitlements.path,
                    document.location.host || document.location.hostname
                );
            }
        }
    }

    function deleteProfileInfo(reload){ // [confirmed]
        //Handles the logout cleanup
        NSCR.config.cookie.loginStatus.domain = '.'+getRoot(window.location.host);
        NSCR.fn.deleteCookie(NSCR.config.cookie.loginStatus.name, NSCR.config.cookie.loginStatus.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.authenticatedUser.name, NSCR.config.cookie.authenticatedUser.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.subscriptions.name, NSCR.config.cookie.subscriptions.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.liveFyreToken.name, NSCR.config.cookie.liveFyreToken.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.gigUID.name, NSCR.config.cookie.gigUID.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.entitlements.name, NSCR.config.cookie.entitlements.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.intStream.name, NSCR.config.cookie.intStream.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.favDriver.name, NSCR.config.cookie.favDriver.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.favDriverID.name, NSCR.config.cookie.favDriverID.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.userRegSource.name, NSCR.config.cookie.userRegSource.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.lastLoginDate.name, NSCR.config.cookie.lastLoginDate.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.regDate.name, NSCR.config.cookie.regDate.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.entitlementsICA.name, NSCR.config.cookie.entitlementsICA.domain);
        NSCR.fn.deleteCookie(NSCR.config.cookie.entitlementsRVP.name, NSCR.config.cookie.entitlementsRVP.domain);

        if(reload){
            location.reload();
        }
    }

    function showLoginRegisterLinks(){ // [confirmed]
        jQuery(".register-login").removeClass("hidden");
        hideMyProfileLink();
    }

    function logoutEventHandler() { // [confirmed]
        showLoginRegisterLinks();
        deleteProfileInfo(true);
    }

    function getAccountInfoResponse(response){ // [confirmed]
        if(isUserLoggedIn()) {
            if (response.errorCode == 0){
                hideLoginRegisterLinks();
                if(typeof NSCR.config.cookie.entitlements !== 'undefined'){
                    var entObj = getEntitleAndPrefFromCookie(NSCR.config.cookie.entitlements, "products:=");
                    if(entObj !== null && !jQuery.isEmptyObject(entObj)){
                        NSCR.userEntitleAndPref.entitlement = entObj;
                    }
                }
                if(typeof NSCR.config.cookie.subscriptions !== 'undefined'){
                    gigya.accounts.getAccountInfo({callback: setUserSubscription});
                    var subsObj = getEntitleAndPrefFromCookie(NSCR.config.cookie.subscriptions, "subscriptions:=");
                    if(subsObj !== null && !jQuery.isEmptyObject(subsObj)){
                        NSCR.userEntitleAndPref.subscription = subsObj;
                    }
                }
                //Extra check to validate that profile image is available in S3 bucket if not then upload it to S3 bucket
                var photoURL = response.profile.photoURL;
                if(typeof photoURL != "undefined" && photoURL != "" && (photoURL.indexOf("cdn.gigya.com") > 0)){
                    uploadProfilePicToS3Bucket(photoURL);
                }
                setUserRegSource(response);
            }else{
                deleteProfileInfo(true);
            }
        }
        else{
            showLoginRegisterLinks();
        }
    }

    function isUserLoggedIn(){ // [confirmed]
        var gls = NSCR.fn.readCookie(NSCR.config.cookie.loginStatus.name);
        if(gls != null && gls == "true"){
            return true;
        }else{
            return false;
        }
    }

    function showMyProfileLink(){ // [confirmed]
        jQuery('#myGarage').removeClass('hidden');
        jQuery('.myGarage').removeClass('hidden');
    }

    function hideLoginRegisterLinks(){ // [confirmed]
        jQuery('#registerOrLogin').addClass('hidden');
        jQuery('.registerOrLogin').addClass('hidden');
        jQuery('#registerAndLogin').addClass('hidden');
        jQuery('#newsMediaLoggedIn').removeClass('hidden');
        jQuery('.raceViewLoginBtn.gigyaLoginDialog').addClass('hidden');
        if(jQuery(".buyLink.raceViewSubscribeBtn").hasClass("hidden")){
            jQuery("#raceViewHeader .headerButtons.buyOrUse").addClass("hidden");
        }
        showMyProfileLink();
    }

    function hideMyProfileLink(){ // [confirmed]
        jQuery('#myGarage').addClass('hidden');
        jQuery('.myGarage').addClass('hidden');
    }

    function getEntitleAndPrefFromCookie(cookieObj, cInfoId){ // [confirmed]
        var entCookie = decodeURIComponent(NSCR.fn.readCookie(cookieObj.name)),
            entValIndex = (entCookie && /^\s*$/.test(entCookie) === false) ? entCookie.indexOf(cInfoId) : -1,
            entObj = null;

        if(entValIndex >= 0){
            var entValCookieTxt = entCookie.substr(entValIndex + cInfoId.length),
                cVal = jQuery.trim(entValCookieTxt.split('|')[0]) || "";
            if(cVal.length > 0){
                var cValArr = cVal.split(','),
                    cValArrLen = cValArr.length;
                if(cValArrLen > 0){
                    entObj = {};
                    for (var i = 0; i < cValArrLen; i++){
                        entObj[cValArr[i]] = i;
                    }
                }
            }
        }
        return entObj;
    }

    function handleUserState(){ // [confirmed]
        gigya.accounts.getAccountInfo({callback: getAccountInfoResponse, include: 'profile,data,subscriptions,regSource'});
    }

    function getURLParameter(paramName){ // [confirmed]

        var sPageURL = window.location.search.substring(1);
        var sURLVariables = sPageURL.split('&');
        var paramVal = "";
        for (var i = 0; i < sURLVariables.length; i++)
        {
            var sParameterName = sURLVariables[i].split('=');
            if (sParameterName[0] == paramName)
            {
                paramVal = sParameterName[1];
                return paramVal;
            }
        }
    }

    function uploadProfilePicToS3Bucket(photoURL){ // [confirmed]
        NSCR.gigyaService.getAccountInfo().done(function(userDetails){
            var queryParams = {
                uid: userDetails.uid,
                uid_signature: userDetails.sig,
                uid_timestamp: userDetails.ts,
                photoURL: photoURL
            };
            queryParams = jQuery.param(queryParams);
            //console.log(queryParams);
            callService(NSCR.config.url.gigyaPhotoEndPoint, "synchProfilePhoto", queryParams);
        });
    }

    /*
     * Load Gigya Screen
     * Loads a Gigya screen from the specified screen set when a user clicks on a
     * link with a valid URL parameter.
     * @param  screenSet  string  Screen set to retrieve the screen from
     * @param  dialog  string  Gigya dialog to open when the page is loaded
     *
     */
    function loadGigyaScreen(screenSet,startScreen){ // [confirmed]
        var ss = (screenSet) ? screenSet:'Login-web';
        var st = (startScreen) ? startScreen:'gigya-login-screen';
        gigya.accounts.showScreenSet({screenSet:ss,startScreen:st});
    }


    function driverListDropDownOptions(){
        if(document.getElementById("favouriteDriverName") && typeof(jQuery) == "function" ){

            var url = 'https://www.nascar.com/json/drivers/?category=';

            //Make Ajax Requests
               var cupDriversRequest = jQuery.ajax({url: url + "nascar-cup-series"});
               var xfinityDriversRequest = jQuery.ajax({url: url + 'xfinity-series'});
               var trucksDriversRequest = jQuery.ajax({url: url + 'gander-outdoors-truck-series'});

           jQuery.when(
               cupDriversRequest,
               xfinityDriversRequest,
               trucksDriversRequest
           ).done(function(cupData,  xfinityData, trucksData){

             //Clearing Current HTML
             document.getElementById("favouriteDriverName").innerHTML = '';

             //Building options Dynamic
                var options = '<option value="Favorite Driver">Favorite Driver</option>';

             //Monster Energy Nascar Cup Series
             options +='<option class="ev-category-option" value="" disabled>NASCAR CUP SERIES</option>';
             cupData[0].response.forEach(function(obj){
                 options +='<option value="'+obj.Nascar_Driver_ID+'">'+obj.Full_Name+'</option>';
             });

             //Xfinity Series
             options +='<option class="ev-category-option" value="" disabled>XFINITY SERIES</option>';
             xfinityData[0].response.forEach(function(obj){
                 options +='<option value="'+obj.Nascar_Driver_ID+'">'+obj.Full_Name+'</option>';
             });

             //Gander Outdoors Truck Series
             options +='<option class="ev-category-option" value="" disabled>GANDER RV & OUTDOORS TRUCK SERIES</option>';
             trucksData[0].response.forEach(function(obj){
                 options +='<option value="'+obj.Nascar_Driver_ID+'">'+obj.Full_Name+'</option>';
             });

             //Adding options
             document.getElementById("favouriteDriverName").innerHTML = options;

           });

        }else{
            console.log("Element favouriteDriverName doenst exist or Jquery is not defined");
        }

    }
