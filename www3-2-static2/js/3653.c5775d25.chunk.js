/*! For license information please see 3653.c5775d25.chunk.js.LICENSE.txt */
"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[3653],{85927:(e,t,n)=>{n.d(t,{Z:()=>a});var o=n(72426),r=n.n(o),l=n(80184);function a(e){const{invoiceData:t}=e;return(0,l.jsxs)(l.Fragment,{children:[(0,l.jsx)("div",{className:"w-100 d-flex justify-content-between align-items-center",children:(0,l.jsxs)("p",{className:"mb-0 Invoice-Number fw-",style:{color:"#999999"},children:["Invoice ",null===t||void 0===t?void 0:t.invoiceNumber]})}),(0,l.jsxs)("div",{className:"w-100 d-flex justify-content-between align-items-center my-3",children:[(0,l.jsx)("img",{src:null!==t&&void 0!==t&&t.doctorProfileImage?null===t||void 0===t?void 0:t.doctorProfileImage:"https://ui-avatars.com/api/?name=".concat("doctorName","&background=6045eb&color=fff"),className:"img-fluid object-fit-cover position-absolute rounded-5",alt:"Payment Invoice"}),(0,l.jsxs)("div",{className:"pt-2 px-3",children:[(0,l.jsxs)("span",{className:"fw-bold Profile-popup-positioning",children:["Dr. ",null===t||void 0===t?void 0:t.doctorName]}),(0,l.jsx)("div",{className:"Popup-date",style:{color:"#999999"},children:r()(null===t||void 0===t?void 0:t.createdDate).format("DD MMM YYYY")})]}),(0,l.jsx)("h6",{children:null===t||void 0===t?void 0:t.status})]}),(0,l.jsx)("hr",{style:{color:"#c8cfd5"}}),(0,l.jsxs)("div",{className:"mt-3 d-flex justify-content-between",children:[(0,l.jsxs)("div",{children:[(0,l.jsx)("label",{style:{color:"#B3B3B3"},children:"From:"}),(0,l.jsx)("h5",{className:"fs-6 fw-bold",children:null===t||void 0===t?void 0:t.patientName}),(0,l.jsx)("p",{className:"Address-FontSize fw-bold mb-2",children:null===t||void 0===t?void 0:t.location}),(0,l.jsx)("small",{children:null===t||void 0===t?void 0:t.email}),(0,l.jsx)("p",{className:"Address-FontSize mt-2",children:null===t||void 0===t?void 0:t.phoneNumber})]}),(0,l.jsxs)("div",{children:[(0,l.jsx)("label",{style:{color:"#B3B3B3"},children:"Bill to:"}),(0,l.jsx)("h5",{className:"fs-6 fw-bold",children:"Family Doc 24/7."}),(0,l.jsx)("p",{className:"Address-FontSize fw-bold mb-2",children:"Fitzwilliam Hall, Fitzwilliam Place, Dublin 2"}),(0,l.jsx)("small",{children:"sales@familydoc247.ie"}),(0,l.jsx)("p",{className:"Address-FontSize mt-2",children:"+353 12630959"})]})]}),(0,l.jsx)("hr",{style:{color:"#c8cfd5"}}),(0,l.jsxs)("div",{children:[(0,l.jsx)("h5",{className:"fs-6 fw-bold mt-4",children:"Description"}),(0,l.jsxs)("div",{className:"d-flex justify-content-between",children:[(0,l.jsx)("h6",{className:"mb-2",style:{color:"#B3B3B3"},children:"Item"}),(0,l.jsx)("h6",{className:"pe-5 mb-2",style:{color:"#B3B3B3"},children:"Fee"})]})]}),(0,l.jsxs)("div",{className:"fs-6 fw-bold d-flex justify-content-between",children:[(0,l.jsx)("h6",{children:null!==t&&void 0!==t&&t.appointmentReason?null===t||void 0===t?void 0:t.appointmentReason:"N/A"}),(0,l.jsx)("h6",{className:"me-5",children:null!==t&&void 0!==t&&t.amount?"$".concat(null===t||void 0===t?void 0:t.amount):"N/A"})]})]})}},63653:(e,t,n)=>{n.r(t),n.d(t,{default:()=>g});var o=n(72791),r=n(95070),l=n(89743),a=n(2677),i=n(36638),s=n(88135),c=n(78820),d=n(2002),u=n(36161),m=n(7692),f=n(39126),h=(n(68639),n(59513)),p=n.n(h),v=n(59434),y=n(72426),b=n.n(y),x=n(21730),j=n(45225),w=n(85927),N=n(80184);function g(){const[e,t]=(0,o.useState)(),[n,h]=(0,o.useState)(!1),[y,g]=(0,o.useState)(),[_,F]=(0,o.useState)(),P=(0,v.I0)(),S=(0,o.useRef)(null),{allPaymentDetails:D}=(0,v.v9)((e=>null===e||void 0===e?void 0:e.PaymentDetails)),I=e=>{h(!0),F(e)},k=[{dataField:"invoiceNumber",text:"Invoice Number",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"}},{dataField:"patientName",text:"Patient Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"}},{dataField:"doctorName",text:"Doctor Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"amount",text:"Amount",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"createdDate",text:"Created Date",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>b()(e).format("YYYY-MM-DD")},{dataField:"status",text:"Status",sort:!1,headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,t)=>(0,N.jsx)("p",{className:"mb-0 text-center py-1 custom-width-class ".concat("Paid"===(null===t||void 0===t?void 0:t.status)&&"active-status"),children:"Paid"===(null===t||void 0===t?void 0:t.status)&&"Paid"})},{dataField:"action",text:"Action",sort:!1,formatter:(e,t)=>(0,N.jsx)(N.Fragment,{children:(0,N.jsx)(c.w8I,{className:"w-100",style:{color:"blue",cursor:"pointer"},onClick:()=>I(t)})}),headerStyle:{backgroundColor:"#F1F1F1"},headerAlign:"center"}],C={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,t,n)=>(0,N.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,N.jsxs)("b",{children:[" ",e," "]})," to ",(0,N.jsx)("b",{children:t})," out of ",(0,N.jsxs)("b",{children:[n," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,o.useEffect)((()=>{const t={isPagination:!0,patientId:null,search:y||null,createdDate:e?b()(e).format("YYYY-MM-DD"):null};P((0,x.sS)(t))}),[P,y,e]),(0,N.jsxs)("div",{className:"doctor-patient-paymentdetails",children:[(0,N.jsx)("h5",{children:"Invoices"}),(0,N.jsxs)(r.Z,{className:"patient-details-card superadmin-date-wrapper",children:[(0,N.jsxs)(l.Z,{className:"pt-3 px-4",children:[(0,N.jsx)(a.Z,{md:3,children:(0,N.jsxs)("span",{className:"d-flex align-self-center",children:[(0,N.jsx)(i.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&g(e.target.value)},onChange:e=>{"Enter"===e.key&&g(e.target.value)},type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing",style:{width:"100%"},"aria-label":"Search"}),(0,N.jsx)(m.Goc,{size:22,className:"searchbar-icon"})]})}),(0,N.jsxs)(a.Z,{md:9,className:"d-flex flex-wrap align-self-center justify-content-end",children:[(0,N.jsx)(p(),{selected:e,onChange:e=>t(e),dateFormat:"dd MMM yyyy",placeholderText:"Date",className:"custom-field-picker dr-date-w px-2"}),(0,N.jsx)(f.zlR,{className:"custom-date-icon",size:18})]})]}),(0,N.jsx)(N.Fragment,{children:(0,N.jsx)("span",{className:"doctor-datatable",children:(0,N.jsx)(d.Z,{columns:k,data:D||[],keyField:"invoiceNumber",pagination:(0,u.ZP)(C),bordered:!1,wrapperClasses:"table-responsive"})})})]}),(0,N.jsxs)(s.Z,{show:n,onHide:()=>h(!1),size:"xl",centered:!0,className:"modal-main",backdrop:"static",children:[(0,N.jsx)(s.Z.Header,{className:"border border-0 Payment-Details-MainClass",closeButton:!0}),(0,N.jsxs)(s.Z.Body,{className:"pt-0",children:[(0,N.jsxs)("div",{className:"w-100 d-flex justify-content-between align-items-center",children:[(0,N.jsxs)("p",{className:"mb-0  Invoice-Number fw-bold",style:{color:"#999999"},children:["Invoice ",null===_||void 0===_?void 0:_.invoiceNumber]}),(0,N.jsxs)("button",{className:"download-button-class ps-4 pe-4 rounded",onClick:()=>{h(!1),setTimeout((function(){var e;null===S||void 0===S||null===(e=S.current)||void 0===e||e.click()}),1e3)},children:[(0,N.jsx)(f.QNI,{className:"me-2"}),"Download"]})]}),(0,N.jsxs)("div",{className:"w-100 d-flex justify-content-between align-items-center my-3",children:[(0,N.jsxs)("div",{className:"d-flex",children:[(0,N.jsx)("div",{className:"position-relative rounded-5",style:{height:"4.5rem",width:"4.5rem",overflow:"hidden",borderRadius:"50%"},children:(0,N.jsx)("img",{src:null!==_&&void 0!==_&&_.doctorProfileImage?null===_||void 0===_?void 0:_.doctorProfileImage:"https://ui-avatars.com/api/?name=".concat("doctorName","&background=6045eb&color=fff"),className:"rounded-5 img-fluid img-obj-cover position-absolute",alt:"Payment Invoice"})}),(0,N.jsxs)("div",{className:"pt-2 px-3",children:[(0,N.jsxs)("span",{className:"fw-bold Profile-popup-positioning",children:["Dr. ",null===_||void 0===_?void 0:_.doctorName]}),(0,N.jsx)("div",{className:"Popup-date",style:{color:"#999999"},children:b()(null===_||void 0===_?void 0:_.createdDate).format("DD MMM YYYY")})]})]}),(0,N.jsx)("div",{children:(0,N.jsx)("p",{className:"download-button-class px-4 rounded",style:{color:"#44BC19",backgroundColor:"#ECFFCC",border:"none"},children:null===_||void 0===_?void 0:_.status})})]}),(0,N.jsx)("hr",{style:{color:"#c8cfd5"}}),(0,N.jsxs)(l.Z,{children:[(0,N.jsx)(a.Z,{lg:6,children:(0,N.jsxs)("div",{className:"mt-3",children:[(0,N.jsx)("label",{htmlFor:"",className:"labeling-Fontsize",style:{color:"#B3B3B3"},children:"From:"}),(0,N.jsx)("h5",{className:"fs-6 fw-bold",children:null===_||void 0===_?void 0:_.patientName}),(0,N.jsx)("p",{className:"Address-FontSize fw-bold mb-2",children:null===_||void 0===_?void 0:_.location}),(0,N.jsx)("small",{children:null===_||void 0===_?void 0:_.email}),(0,N.jsx)("p",{className:"Address-FontSize mt-2",children:null===_||void 0===_?void 0:_.phoneNumber})]})}),(0,N.jsx)(a.Z,{lg:6,className:"Bill-To-Class",children:(0,N.jsxs)("div",{className:"mt-3",children:[(0,N.jsx)("label",{htmlFor:"",className:"labeling-Fontsize",children:"Bill to:"}),(0,N.jsx)("h5",{className:"fs-6 fw-bold",children:"Family Doc 24/7."}),(0,N.jsx)("p",{className:"Address-FontSize fw-bold mb-2",children:"Fitzwilliam Hall, Fitzwilliam Place, Dublin 2"}),(0,N.jsx)("small",{children:"sales@familydoc247.ie"}),(0,N.jsx)("p",{className:"Address-FontSize mt-2",children:"+353 12630959"})]})})]}),(0,N.jsx)("hr",{style:{color:"#c8cfd5"}}),(0,N.jsxs)("div",{children:[(0,N.jsx)("h5",{className:"fs-6 fw-bold mt-4",children:"Description"}),(0,N.jsxs)("div",{className:"d-flex justify-content-between mt-4 Description-Bar",style:{backgroundColor:"#F1F1F1",padding:"5px"},children:[(0,N.jsx)("h6",{className:"ps-3 mb-2",style:{color:"#999999"},children:"Item"}),(0,N.jsx)("h6",{className:"pe-5 mb-2",style:{color:"#999999"},children:"Fee"})]})]}),(0,N.jsxs)("div",{className:"fs-6 fw-bold d-flex justify-content-between mt-4",children:[(0,N.jsx)("h6",{style:{color:"#1A1A1A"},className:"fw-bold Description-Bar px-2",children:null!==_&&void 0!==_&&_.appointmentReason?null===_||void 0===_?void 0:_.appointmentReason:"N/A"}),(0,N.jsx)("h6",{className:"fw-bold me-5",children:null!==_&&void 0!==_&&_.amount?"$".concat(null===_||void 0===_?void 0:_.amount):"N/A"})]})]})]}),(0,N.jsx)(j.ZP,{trigger:(0,N.jsxs)("button",{ref:S,className:"border-0 px-3 py-2 rounded-2 d-none",children:[(0,N.jsx)(f.QNI,{size:20})," Download PDF"]}),children:(0,N.jsx)(w.Z,{invoiceData:_})})]})}},45225:(e,t,n)=>{var o=n(43735),r=n(72791),l=n(54164),a=function(e){function t(t){var n=e.call(this,t)||this;return n.rootId="react-components-print",n.handlePrint=function(){document.body.insertAdjacentElement("afterbegin",n.rootEl),window.onafterprint=n.onPrintClose,window.print()},n.onPrintClose=function(){window.onafterprint=function(){return null},n.rootEl.remove()},n.createDivElement=function(e,t){var n=document.createElement("div");return e&&n.setAttribute("id",e),t&&n.setAttribute("class",t),n},n.createStyle=function(){return r.createElement("style",{dangerouslySetInnerHTML:{__html:"\n      #"+n.rootId+" {\n        display: none;\n      }\n\n      @media print {\n        body > *:not(#"+n.rootId+") {\n          display: none;\n        }\n\n        #"+n.rootId+" {\n          display: block;\n        }\n      }\n    "}})},n.rootEl=n.createDivElement(n.rootId,t.className),n}return o.__extends(t,e),t.prototype.render=function(){var e=this.props,t=e.children,n=e.trigger,a=r.createElement(r.Fragment,null,this.createStyle(),t);return r.createElement(r.Fragment,null,r.cloneElement(n,o.__assign({},n.props,{onClick:this.handlePrint})),l.createPortal(a,this.rootEl))},t}(r.Component);t.ZP=a},43735:(e,t,n)=>{n.r(t),n.d(t,{__assign:()=>l,__asyncDelegator:()=>j,__asyncGenerator:()=>x,__asyncValues:()=>w,__await:()=>b,__awaiter:()=>d,__classPrivateFieldGet:()=>F,__classPrivateFieldSet:()=>P,__createBinding:()=>m,__decorate:()=>i,__exportStar:()=>f,__extends:()=>r,__generator:()=>u,__importDefault:()=>_,__importStar:()=>g,__makeTemplateObject:()=>N,__metadata:()=>c,__param:()=>s,__read:()=>p,__rest:()=>a,__spread:()=>v,__spreadArrays:()=>y,__values:()=>h});var o=function(e,t){return o=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,t){e.__proto__=t}||function(e,t){for(var n in t)t.hasOwnProperty(n)&&(e[n]=t[n])},o(e,t)};function r(e,t){function n(){this.constructor=e}o(e,t),e.prototype=null===t?Object.create(t):(n.prototype=t.prototype,new n)}var l=function(){return l=Object.assign||function(e){for(var t,n=1,o=arguments.length;n<o;n++)for(var r in t=arguments[n])Object.prototype.hasOwnProperty.call(t,r)&&(e[r]=t[r]);return e},l.apply(this,arguments)};function a(e,t){var n={};for(var o in e)Object.prototype.hasOwnProperty.call(e,o)&&t.indexOf(o)<0&&(n[o]=e[o]);if(null!=e&&"function"===typeof Object.getOwnPropertySymbols){var r=0;for(o=Object.getOwnPropertySymbols(e);r<o.length;r++)t.indexOf(o[r])<0&&Object.prototype.propertyIsEnumerable.call(e,o[r])&&(n[o[r]]=e[o[r]])}return n}function i(e,t,n,o){var r,l=arguments.length,a=l<3?t:null===o?o=Object.getOwnPropertyDescriptor(t,n):o;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)a=Reflect.decorate(e,t,n,o);else for(var i=e.length-1;i>=0;i--)(r=e[i])&&(a=(l<3?r(a):l>3?r(t,n,a):r(t,n))||a);return l>3&&a&&Object.defineProperty(t,n,a),a}function s(e,t){return function(n,o){t(n,o,e)}}function c(e,t){if("object"===typeof Reflect&&"function"===typeof Reflect.metadata)return Reflect.metadata(e,t)}function d(e,t,n,o){return new(n||(n=Promise))((function(r,l){function a(e){try{s(o.next(e))}catch(t){l(t)}}function i(e){try{s(o.throw(e))}catch(t){l(t)}}function s(e){var t;e.done?r(e.value):(t=e.value,t instanceof n?t:new n((function(e){e(t)}))).then(a,i)}s((o=o.apply(e,t||[])).next())}))}function u(e,t){var n,o,r,l,a={label:0,sent:function(){if(1&r[0])throw r[1];return r[1]},trys:[],ops:[]};return l={next:i(0),throw:i(1),return:i(2)},"function"===typeof Symbol&&(l[Symbol.iterator]=function(){return this}),l;function i(l){return function(i){return function(l){if(n)throw new TypeError("Generator is already executing.");for(;a;)try{if(n=1,o&&(r=2&l[0]?o.return:l[0]?o.throw||((r=o.return)&&r.call(o),0):o.next)&&!(r=r.call(o,l[1])).done)return r;switch(o=0,r&&(l=[2&l[0],r.value]),l[0]){case 0:case 1:r=l;break;case 4:return a.label++,{value:l[1],done:!1};case 5:a.label++,o=l[1],l=[0];continue;case 7:l=a.ops.pop(),a.trys.pop();continue;default:if(!(r=(r=a.trys).length>0&&r[r.length-1])&&(6===l[0]||2===l[0])){a=0;continue}if(3===l[0]&&(!r||l[1]>r[0]&&l[1]<r[3])){a.label=l[1];break}if(6===l[0]&&a.label<r[1]){a.label=r[1],r=l;break}if(r&&a.label<r[2]){a.label=r[2],a.ops.push(l);break}r[2]&&a.ops.pop(),a.trys.pop();continue}l=t.call(e,a)}catch(i){l=[6,i],o=0}finally{n=r=0}if(5&l[0])throw l[1];return{value:l[0]?l[1]:void 0,done:!0}}([l,i])}}}function m(e,t,n,o){void 0===o&&(o=n),e[o]=t[n]}function f(e,t){for(var n in e)"default"===n||t.hasOwnProperty(n)||(t[n]=e[n])}function h(e){var t="function"===typeof Symbol&&Symbol.iterator,n=t&&e[t],o=0;if(n)return n.call(e);if(e&&"number"===typeof e.length)return{next:function(){return e&&o>=e.length&&(e=void 0),{value:e&&e[o++],done:!e}}};throw new TypeError(t?"Object is not iterable.":"Symbol.iterator is not defined.")}function p(e,t){var n="function"===typeof Symbol&&e[Symbol.iterator];if(!n)return e;var o,r,l=n.call(e),a=[];try{for(;(void 0===t||t-- >0)&&!(o=l.next()).done;)a.push(o.value)}catch(i){r={error:i}}finally{try{o&&!o.done&&(n=l.return)&&n.call(l)}finally{if(r)throw r.error}}return a}function v(){for(var e=[],t=0;t<arguments.length;t++)e=e.concat(p(arguments[t]));return e}function y(){for(var e=0,t=0,n=arguments.length;t<n;t++)e+=arguments[t].length;var o=Array(e),r=0;for(t=0;t<n;t++)for(var l=arguments[t],a=0,i=l.length;a<i;a++,r++)o[r]=l[a];return o}function b(e){return this instanceof b?(this.v=e,this):new b(e)}function x(e,t,n){if(!Symbol.asyncIterator)throw new TypeError("Symbol.asyncIterator is not defined.");var o,r=n.apply(e,t||[]),l=[];return o={},a("next"),a("throw"),a("return"),o[Symbol.asyncIterator]=function(){return this},o;function a(e){r[e]&&(o[e]=function(t){return new Promise((function(n,o){l.push([e,t,n,o])>1||i(e,t)}))})}function i(e,t){try{(n=r[e](t)).value instanceof b?Promise.resolve(n.value.v).then(s,c):d(l[0][2],n)}catch(o){d(l[0][3],o)}var n}function s(e){i("next",e)}function c(e){i("throw",e)}function d(e,t){e(t),l.shift(),l.length&&i(l[0][0],l[0][1])}}function j(e){var t,n;return t={},o("next"),o("throw",(function(e){throw e})),o("return"),t[Symbol.iterator]=function(){return this},t;function o(o,r){t[o]=e[o]?function(t){return(n=!n)?{value:b(e[o](t)),done:"return"===o}:r?r(t):t}:r}}function w(e){if(!Symbol.asyncIterator)throw new TypeError("Symbol.asyncIterator is not defined.");var t,n=e[Symbol.asyncIterator];return n?n.call(e):(e=h(e),t={},o("next"),o("throw"),o("return"),t[Symbol.asyncIterator]=function(){return this},t);function o(n){t[n]=e[n]&&function(t){return new Promise((function(o,r){(function(e,t,n,o){Promise.resolve(o).then((function(t){e({value:t,done:n})}),t)})(o,r,(t=e[n](t)).done,t.value)}))}}}function N(e,t){return Object.defineProperty?Object.defineProperty(e,"raw",{value:t}):e.raw=t,e}function g(e){if(e&&e.__esModule)return e;var t={};if(null!=e)for(var n in e)Object.hasOwnProperty.call(e,n)&&(t[n]=e[n]);return t.default=e,t}function _(e){return e&&e.__esModule?e:{default:e}}function F(e,t){if(!t.has(e))throw new TypeError("attempted to get private field on non-instance");return t.get(e)}function P(e,t,n){if(!t.has(e))throw new TypeError("attempted to set private field on non-instance");return t.set(e,n),n}}}]);
//# sourceMappingURL=3653.c5775d25.chunk.js.map