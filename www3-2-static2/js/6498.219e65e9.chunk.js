/*! For license information please see 6498.219e65e9.chunk.js.LICENSE.txt */
(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6498],{25666:(t,e,n)=>{"use strict";n.d(e,{Z:()=>a});var o=n(39007),r=n(73201),i=n(72791);const a=function(t){let{children:e,in:n,onExited:a,mountOnEnter:s,unmountOnExit:c}=t;const l=(0,i.useRef)(null),u=(0,i.useRef)(n),h=(0,o.Z)(a);(0,i.useEffect)((()=>{n?u.current=!0:h(l.current)}),[n,h]);const d=(0,r.Z)(l,e.ref),f=(0,i.cloneElement)(e,{ref:d});return n?f:c||!u.current&&s?null:f}},95070:(t,e,n)=>{"use strict";n.d(e,{Z:()=>T});var o=n(81694),r=n.n(o),i=n(72791),a=n(10162),s=n(80184);const c=i.forwardRef(((t,e)=>{let{className:n,bsPrefix:o,as:i="div",...c}=t;return o=(0,a.vE)(o,"card-body"),(0,s.jsx)(i,{ref:e,className:r()(n,o),...c})}));c.displayName="CardBody";const l=c,u=i.forwardRef(((t,e)=>{let{className:n,bsPrefix:o,as:i="div",...c}=t;return o=(0,a.vE)(o,"card-footer"),(0,s.jsx)(i,{ref:e,className:r()(n,o),...c})}));u.displayName="CardFooter";const h=u;var d=n(96040);const f=i.forwardRef(((t,e)=>{let{bsPrefix:n,className:o,as:c="div",...l}=t;const u=(0,a.vE)(n,"card-header"),h=(0,i.useMemo)((()=>({cardHeaderBsPrefix:u})),[u]);return(0,s.jsx)(d.Z.Provider,{value:h,children:(0,s.jsx)(c,{ref:e,...l,className:r()(o,u)})})}));f.displayName="CardHeader";const p=f,v=i.forwardRef(((t,e)=>{let{bsPrefix:n,className:o,variant:i,as:c="img",...l}=t;const u=(0,a.vE)(n,"card-img");return(0,s.jsx)(c,{ref:e,className:r()(i?"".concat(u,"-").concat(i):u,o),...l})}));v.displayName="CardImg";const m=v,_=i.forwardRef(((t,e)=>{let{className:n,bsPrefix:o,as:i="div",...c}=t;return o=(0,a.vE)(o,"card-img-overlay"),(0,s.jsx)(i,{ref:e,className:r()(n,o),...c})}));_.displayName="CardImgOverlay";const y=_,x=i.forwardRef(((t,e)=>{let{className:n,bsPrefix:o,as:i="a",...c}=t;return o=(0,a.vE)(o,"card-link"),(0,s.jsx)(i,{ref:e,className:r()(n,o),...c})}));x.displayName="CardLink";const g=x;var w=n(27472);const b=(0,w.Z)("h6"),P=i.forwardRef(((t,e)=>{let{className:n,bsPrefix:o,as:i=b,...c}=t;return o=(0,a.vE)(o,"card-subtitle"),(0,s.jsx)(i,{ref:e,className:r()(n,o),...c})}));P.displayName="CardSubtitle";const E=P,C=i.forwardRef(((t,e)=>{let{className:n,bsPrefix:o,as:i="p",...c}=t;return o=(0,a.vE)(o,"card-text"),(0,s.jsx)(i,{ref:e,className:r()(n,o),...c})}));C.displayName="CardText";const N=C,D=(0,w.Z)("h5"),M=i.forwardRef(((t,e)=>{let{className:n,bsPrefix:o,as:i=D,...c}=t;return o=(0,a.vE)(o,"card-title"),(0,s.jsx)(i,{ref:e,className:r()(n,o),...c})}));M.displayName="CardTitle";const k=M,R=i.forwardRef(((t,e)=>{let{bsPrefix:n,className:o,bg:i,text:c,border:u,body:h=!1,children:d,as:f="div",...p}=t;const v=(0,a.vE)(n,"card");return(0,s.jsx)(f,{ref:e,...p,className:r()(o,v,i&&"bg-".concat(i),c&&"text-".concat(c),u&&"border-".concat(u)),children:h?(0,s.jsx)(l,{children:d}):d})}));R.displayName="Card";const T=Object.assign(R,{Img:m,Title:k,Subtitle:E,Body:l,Link:g,Text:N,Header:p,Footer:h,ImgOverlay:y})},96040:(t,e,n)=>{"use strict";n.d(e,{Z:()=>r});const o=n(72791).createContext(null);o.displayName="CardHeaderContext";const r=o},47022:(t,e,n)=>{"use strict";n.d(e,{Z:()=>l});var o=n(81694),r=n.n(o),i=n(72791),a=n(10162),s=n(80184);const c=i.forwardRef(((t,e)=>{let{bsPrefix:n,fluid:o=!1,as:i="div",className:c,...l}=t;const u=(0,a.vE)(n,"container"),h="string"===typeof o?"-".concat(o):"-fluid";return(0,s.jsx)(i,{ref:e,...l,className:r()(c,o?"".concat(u).concat(h):u)})}));c.displayName="Container";const l=c},84934:(t,e,n)=>{"use strict";n.d(e,{Z:()=>o});const o=n(72791).createContext({})},53392:(t,e,n)=>{"use strict";n.d(e,{Z:()=>h});var o=n(81694),r=n.n(o),i=n(72791),a=(n(42391),n(2677)),s=n(84934),c=n(10162),l=n(80184);const u=i.forwardRef(((t,e)=>{let{as:n="label",bsPrefix:o,column:u=!1,visuallyHidden:h=!1,className:d,htmlFor:f,...p}=t;const{controlId:v}=(0,i.useContext)(s.Z);o=(0,c.vE)(o,"form-label");let m="col-form-label";"string"===typeof u&&(m="".concat(m," ").concat(m,"-").concat(u));const _=r()(d,o,h&&"visually-hidden",u&&m);return f=f||v,u?(0,l.jsx)(a.Z,{ref:e,as:"label",className:_,htmlFor:f,...p}):(0,l.jsx)(n,{ref:e,className:_,htmlFor:f,...p})}));u.displayName="FormLabel";const h=u},27472:(t,e,n)=>{"use strict";n.d(e,{Z:()=>s});var o=n(72791),r=n(81694),i=n.n(r),a=n(80184);const s=t=>o.forwardRef(((e,n)=>(0,a.jsx)("div",{...e,ref:n,className:i()(e.className,t)})))},51276:function(t,e,n){var o,r,i,a;t.exports=(o=n(52007),r=n(72791),i=n(20354),a=n(59590),function(t){function e(o){if(n[o])return n[o].exports;var r=n[o]={exports:{},id:o,loaded:!1};return t[o].call(r.exports,r,r.exports,e),r.loaded=!0,r.exports}var n={};return e.m=t,e.c=n,e.p="",e(0)}([function(t,e,n){"use strict";function o(t){return t&&t.__esModule?t:{default:t}}function r(t,e){var n={};for(var o in t)e.indexOf(o)>=0||Object.prototype.hasOwnProperty.call(t,o)&&(n[o]=t[o]);return n}function i(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")}function a(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e}function s(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)}Object.defineProperty(e,"__esModule",{value:!0});var c=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(t[o]=n[o])}return t},l=function(){function t(t,e){for(var n=0;n<e.length;n++){var o=e[n];o.enumerable=o.enumerable||!1,o.configurable=!0,"value"in o&&(o.writable=!0),Object.defineProperty(t,o.key,o)}}return function(e,n,o){return n&&t(e.prototype,n),o&&t(e,o),e}}(),u=o(n(1)),h=n(2),d=o(h),f=o(n(3)),p=o(n(4)),v=function(t){function e(){var t,n,o;i(this,e);for(var s=arguments.length,c=Array(s),l=0;l<s;l++)c[l]=arguments[l];return n=o=a(this,(t=e.__proto__||Object.getPrototypeOf(e)).call.apply(t,[this].concat(c))),o._sigPad=null,o._excludeOurProps=function(){var t=o.props;return t.canvasProps,t.clearOnResize,r(t,["canvasProps","clearOnResize"])},o.getCanvas=function(){return o._canvas},o.getTrimmedCanvas=function(){var t=document.createElement("canvas");return t.width=o._canvas.width,t.height=o._canvas.height,t.getContext("2d").drawImage(o._canvas,0,0),(0,p.default)(t)},o.getSignaturePad=function(){return o._sigPad},o._checkClearOnResize=function(){o.props.clearOnResize&&o._resizeCanvas()},o._resizeCanvas=function(){var t=o.props.canvasProps||{},e=t.width,n=t.height;if(!e||!n){var r=o._canvas,i=Math.max(window.devicePixelRatio||1,1);e||(r.width=r.offsetWidth*i),n||(r.height=r.offsetHeight*i),r.getContext("2d").scale(i,i),o.clear()}},o.on=function(){return window.addEventListener("resize",o._checkClearOnResize),o._sigPad.on()},o.off=function(){return window.removeEventListener("resize",o._checkClearOnResize),o._sigPad.off()},o.clear=function(){return o._sigPad.clear()},o.isEmpty=function(){return o._sigPad.isEmpty()},o.fromDataURL=function(t,e){return o._sigPad.fromDataURL(t,e)},o.toDataURL=function(t,e){return o._sigPad.toDataURL(t,e)},o.fromData=function(t){return o._sigPad.fromData(t)},o.toData=function(){return o._sigPad.toData()},a(o,n)}return s(e,t),l(e,[{key:"componentDidMount",value:function(){this._sigPad=new f.default(this._canvas,this._excludeOurProps()),this._resizeCanvas(),this.on()}},{key:"componentWillUnmount",value:function(){this.off()}},{key:"componentDidUpdate",value:function(){Object.assign(this._sigPad,this._excludeOurProps())}},{key:"render",value:function(){var t=this,e=this.props.canvasProps;return d.default.createElement("canvas",c({ref:function(e){t._canvas=e}},e))}}]),e}(h.Component);v.propTypes={velocityFilterWeight:u.default.number,minWidth:u.default.number,maxWidth:u.default.number,minDistance:u.default.number,dotSize:u.default.oneOfType([u.default.number,u.default.func]),penColor:u.default.string,throttle:u.default.number,onEnd:u.default.func,onBegin:u.default.func,canvasProps:u.default.object,clearOnResize:u.default.bool},v.defaultProps={clearOnResize:!0},e.default=v},function(t,e){t.exports=o},function(t,e){t.exports=r},function(t,e){t.exports=i},function(t,e){t.exports=a}]))},59590:function(t){t.exports=function(t){function e(o){if(n[o])return n[o].exports;var r=n[o]={exports:{},id:o,loaded:!1};return t[o].call(r.exports,r,r.exports,e),r.loaded=!0,r.exports}var n={};return e.m=t,e.c=n,e.p="",e(0)}([function(t,e){"use strict";function n(t){var e=t.getContext("2d"),n=t.width,o=t.height,r=e.getImageData(0,0,n,o).data,s=i(!0,n,o,r),c=i(!1,n,o,r),l=a(!0,n,o,r),u=a(!1,n,o,r)-l+1,h=c-s+1,d=e.getImageData(l,s,u,h);return t.width=u,t.height=h,e.clearRect(0,0,u,h),e.putImageData(d,0,0),t}function o(t,e,n,o){return{red:o[4*(n*e+t)],green:o[4*(n*e+t)+1],blue:o[4*(n*e+t)+2],alpha:o[4*(n*e+t)+3]}}function r(t,e,n,r){return o(t,e,n,r).alpha}function i(t,e,n,o){for(var i=t?1:-1,a=t?0:n-1;t?a<n:a>-1;a+=i)for(var s=0;s<e;s++)if(r(s,a,e,o))return a;return null}function a(t,e,n,o){for(var i=t?1:-1,a=t?0:e-1;t?a<e:a>-1;a+=i)for(var s=0;s<n;s++)if(r(a,s,e,o))return a;return null}Object.defineProperty(e,"__esModule",{value:!0}),e.default=n}])},20354:(t,e,n)=>{"use strict";function o(t,e,n){this.x=t,this.y=e,this.time=n||(new Date).getTime()}function r(t,e,n,o){this.startPoint=t,this.control1=e,this.control2=n,this.endPoint=o}function i(t,e){var n=this,o=e||{};this.velocityFilterWeight=o.velocityFilterWeight||.7,this.minWidth=o.minWidth||.5,this.maxWidth=o.maxWidth||2.5,this.throttle="throttle"in o?o.throttle:16,this.minDistance="minDistance"in o?o.minDistance:5,this.throttle?this._strokeMoveUpdate=function(t,e,n){var o,r,i,a=null,s=0;n||(n={});var c=function(){s=!1===n.leading?0:Date.now(),a=null,i=t.apply(o,r),a||(o=r=null)};return function(){var l=Date.now();s||!1!==n.leading||(s=l);var u=e-(l-s);return o=this,r=arguments,u<=0||u>e?(a&&(clearTimeout(a),a=null),s=l,i=t.apply(o,r),a||(o=r=null)):a||!1===n.trailing||(a=setTimeout(c,u)),i}}(i.prototype._strokeUpdate,this.throttle):this._strokeMoveUpdate=i.prototype._strokeUpdate,this.dotSize=o.dotSize||function(){return(this.minWidth+this.maxWidth)/2},this.penColor=o.penColor||"black",this.backgroundColor=o.backgroundColor||"rgba(0,0,0,0)",this.onBegin=o.onBegin,this.onEnd=o.onEnd,this._canvas=t,this._ctx=t.getContext("2d"),this.clear(),this._handleMouseDown=function(t){1===t.which&&(n._mouseButtonDown=!0,n._strokeBegin(t))},this._handleMouseMove=function(t){n._mouseButtonDown&&n._strokeMoveUpdate(t)},this._handleMouseUp=function(t){1===t.which&&n._mouseButtonDown&&(n._mouseButtonDown=!1,n._strokeEnd(t))},this._handleTouchStart=function(t){if(1===t.targetTouches.length){var e=t.changedTouches[0];n._strokeBegin(e)}},this._handleTouchMove=function(t){t.preventDefault();var e=t.targetTouches[0];n._strokeMoveUpdate(e)},this._handleTouchEnd=function(t){t.target===n._canvas&&(t.preventDefault(),n._strokeEnd(t))},this.on()}n.r(e),n.d(e,{default:()=>a}),o.prototype.velocityFrom=function(t){return this.time!==t.time?this.distanceTo(t)/(this.time-t.time):1},o.prototype.distanceTo=function(t){return Math.sqrt(Math.pow(this.x-t.x,2)+Math.pow(this.y-t.y,2))},o.prototype.equals=function(t){return this.x===t.x&&this.y===t.y&&this.time===t.time},r.prototype.length=function(){for(var t=0,e=void 0,n=void 0,o=0;o<=10;o+=1){var r=o/10,i=this._point(r,this.startPoint.x,this.control1.x,this.control2.x,this.endPoint.x),a=this._point(r,this.startPoint.y,this.control1.y,this.control2.y,this.endPoint.y);if(o>0){var s=i-e,c=a-n;t+=Math.sqrt(s*s+c*c)}e=i,n=a}return t},r.prototype._point=function(t,e,n,o,r){return e*(1-t)*(1-t)*(1-t)+3*n*(1-t)*(1-t)*t+3*o*(1-t)*t*t+r*t*t*t},i.prototype.clear=function(){var t=this._ctx,e=this._canvas;t.fillStyle=this.backgroundColor,t.clearRect(0,0,e.width,e.height),t.fillRect(0,0,e.width,e.height),this._data=[],this._reset(),this._isEmpty=!0},i.prototype.fromDataURL=function(t){var e=this,n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},o=new Image,r=n.ratio||window.devicePixelRatio||1,i=n.width||this._canvas.width/r,a=n.height||this._canvas.height/r;this._reset(),o.src=t,o.onload=function(){e._ctx.drawImage(o,0,0,i,a)},this._isEmpty=!1},i.prototype.toDataURL=function(t){var e;if("image/svg+xml"===t)return this._toSVG();for(var n=arguments.length,o=Array(n>1?n-1:0),r=1;r<n;r++)o[r-1]=arguments[r];return(e=this._canvas).toDataURL.apply(e,[t].concat(o))},i.prototype.on=function(){this._handleMouseEvents(),this._handleTouchEvents()},i.prototype.off=function(){this._canvas.removeEventListener("mousedown",this._handleMouseDown),this._canvas.removeEventListener("mousemove",this._handleMouseMove),document.removeEventListener("mouseup",this._handleMouseUp),this._canvas.removeEventListener("touchstart",this._handleTouchStart),this._canvas.removeEventListener("touchmove",this._handleTouchMove),this._canvas.removeEventListener("touchend",this._handleTouchEnd)},i.prototype.isEmpty=function(){return this._isEmpty},i.prototype._strokeBegin=function(t){this._data.push([]),this._reset(),this._strokeUpdate(t),"function"===typeof this.onBegin&&this.onBegin(t)},i.prototype._strokeUpdate=function(t){var e=t.clientX,n=t.clientY,o=this._createPoint(e,n),r=this._data[this._data.length-1],i=r&&r[r.length-1],a=i&&o.distanceTo(i)<this.minDistance;if(!i||!a){var s=this._addPoint(o),c=s.curve,l=s.widths;c&&l&&this._drawCurve(c,l.start,l.end),this._data[this._data.length-1].push({x:o.x,y:o.y,time:o.time,color:this.penColor})}},i.prototype._strokeEnd=function(t){var e=this.points.length>2,n=this.points[0];if(!e&&n&&this._drawDot(n),n){var o=this._data[this._data.length-1],r=o[o.length-1];n.equals(r)||o.push({x:n.x,y:n.y,time:n.time,color:this.penColor})}"function"===typeof this.onEnd&&this.onEnd(t)},i.prototype._handleMouseEvents=function(){this._mouseButtonDown=!1,this._canvas.addEventListener("mousedown",this._handleMouseDown),this._canvas.addEventListener("mousemove",this._handleMouseMove),document.addEventListener("mouseup",this._handleMouseUp)},i.prototype._handleTouchEvents=function(){this._canvas.style.msTouchAction="none",this._canvas.style.touchAction="none",this._canvas.addEventListener("touchstart",this._handleTouchStart),this._canvas.addEventListener("touchmove",this._handleTouchMove),this._canvas.addEventListener("touchend",this._handleTouchEnd)},i.prototype._reset=function(){this.points=[],this._lastVelocity=0,this._lastWidth=(this.minWidth+this.maxWidth)/2,this._ctx.fillStyle=this.penColor},i.prototype._createPoint=function(t,e,n){var r=this._canvas.getBoundingClientRect();return new o(t-r.left,e-r.top,n||(new Date).getTime())},i.prototype._addPoint=function(t){var e=this.points;if(e.push(t),e.length>2){3===e.length&&e.unshift(e[0]);var n=this._calculateCurveControlPoints(e[0],e[1],e[2]).c2,o=this._calculateCurveControlPoints(e[1],e[2],e[3]).c1,i=new r(e[1],n,o,e[2]),a=this._calculateCurveWidths(i);return e.shift(),{curve:i,widths:a}}return{}},i.prototype._calculateCurveControlPoints=function(t,e,n){var r=t.x-e.x,i=t.y-e.y,a=e.x-n.x,s=e.y-n.y,c=(t.x+e.x)/2,l=(t.y+e.y)/2,u=(e.x+n.x)/2,h=(e.y+n.y)/2,d=Math.sqrt(r*r+i*i),f=Math.sqrt(a*a+s*s),p=f/(d+f),v=u+(c-u)*p,m=h+(l-h)*p,_=e.x-v,y=e.y-m;return{c1:new o(c+_,l+y),c2:new o(u+_,h+y)}},i.prototype._calculateCurveWidths=function(t){var e=t.startPoint,n=t.endPoint,o={start:null,end:null},r=this.velocityFilterWeight*n.velocityFrom(e)+(1-this.velocityFilterWeight)*this._lastVelocity,i=this._strokeWidth(r);return o.start=this._lastWidth,o.end=i,this._lastVelocity=r,this._lastWidth=i,o},i.prototype._strokeWidth=function(t){return Math.max(this.maxWidth/(t+1),this.minWidth)},i.prototype._drawPoint=function(t,e,n){var o=this._ctx;o.moveTo(t,e),o.arc(t,e,n,0,2*Math.PI,!1),this._isEmpty=!1},i.prototype._drawCurve=function(t,e,n){var o=this._ctx,r=n-e,i=Math.floor(t.length());o.beginPath();for(var a=0;a<i;a+=1){var s=a/i,c=s*s,l=c*s,u=1-s,h=u*u,d=h*u,f=d*t.startPoint.x;f+=3*h*s*t.control1.x,f+=3*u*c*t.control2.x,f+=l*t.endPoint.x;var p=d*t.startPoint.y;p+=3*h*s*t.control1.y,p+=3*u*c*t.control2.y,p+=l*t.endPoint.y;var v=e+l*r;this._drawPoint(f,p,v)}o.closePath(),o.fill()},i.prototype._drawDot=function(t){var e=this._ctx,n="function"===typeof this.dotSize?this.dotSize():this.dotSize;e.beginPath(),this._drawPoint(t.x,t.y,n),e.closePath(),e.fill()},i.prototype._fromData=function(t,e,n){for(var r=0;r<t.length;r+=1){var i=t[r];if(i.length>1)for(var a=0;a<i.length;a+=1){var s=i[a],c=new o(s.x,s.y,s.time),l=s.color;if(0===a)this.penColor=l,this._reset(),this._addPoint(c);else if(a!==i.length-1){var u=this._addPoint(c),h=u.curve,d=u.widths;h&&d&&e(h,d,l)}}else this._reset(),n(i[0])}},i.prototype._toSVG=function(){var t=this,e=this._data,n=this._canvas,o=Math.max(window.devicePixelRatio||1,1),r=n.width/o,i=n.height/o,a=document.createElementNS("http://www.w3.org/2000/svg","svg");a.setAttributeNS(null,"width",n.width),a.setAttributeNS(null,"height",n.height),this._fromData(e,(function(t,e,n){var o=document.createElement("path");if(!isNaN(t.control1.x)&&!isNaN(t.control1.y)&&!isNaN(t.control2.x)&&!isNaN(t.control2.y)){var r="M "+t.startPoint.x.toFixed(3)+","+t.startPoint.y.toFixed(3)+" C "+t.control1.x.toFixed(3)+","+t.control1.y.toFixed(3)+" "+t.control2.x.toFixed(3)+","+t.control2.y.toFixed(3)+" "+t.endPoint.x.toFixed(3)+","+t.endPoint.y.toFixed(3);o.setAttribute("d",r),o.setAttribute("stroke-width",(2.25*e.end).toFixed(3)),o.setAttribute("stroke",n),o.setAttribute("fill","none"),o.setAttribute("stroke-linecap","round"),a.appendChild(o)}}),(function(e){var n=document.createElement("circle"),o="function"===typeof t.dotSize?t.dotSize():t.dotSize;n.setAttribute("r",o),n.setAttribute("cx",e.x),n.setAttribute("cy",e.y),n.setAttribute("fill",e.color),a.appendChild(n)}));var s='<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 '+r+" "+i+'" width="'+r+'" height="'+i+'">',c=a.innerHTML;if(void 0===c){var l=document.createElement("dummy"),u=a.childNodes;l.innerHTML="";for(var h=0;h<u.length;h+=1)l.appendChild(u[h].cloneNode(!0));c=l.innerHTML}return"data:image/svg+xml;base64,"+btoa(s+c+"</svg>")},i.prototype.fromData=function(t){var e=this;this.clear(),this._fromData(t,(function(t,n){return e._drawCurve(t,n.start,n.end)}),(function(t){return e._drawDot(t)})),this._data=t},i.prototype.toData=function(){return this._data};const a=i}}]);
//# sourceMappingURL=6498.219e65e9.chunk.js.map