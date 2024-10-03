"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[3661],{52268:(e,o,i)=>{i.d(o,{Tf:()=>t,_Y:()=>d,bA:()=>l,df:()=>a,lt:()=>s,sP:()=>n});const l=[{lookupId:6,value:"Nurse"},{lookupId:7,value:"Receptionist"}],n=[{lookupId:101,value:"Male"},{lookupId:102,value:"Female"},{lookupId:103,value:"Other"}],t={Destroyed:"destroyed",Error:"error",Incoming:"incoming",Registered:"registered",Registering:"registering",TokenWillExpire:"tokenWillExpire",Unregistered:"unregistered"},s={Connected:"connected",Accept:"accept",Audio:"audio",Cancel:"cancel",Disconnect:"disconnect",Error:"error",Mute:"mute",Reconnected:"reconnected",Reconnecting:"reconnecting",Reject:"reject",Ringing:"ringing",Sample:"sample",Volume:"volume",WarningCleared:"warning-cleared",Warning:"warning"},d=[{lookupId:401,name:"Multiple Choice",value:"Radio"},{lookupId:402,name:"Checkbox",value:"Checkbox"},{lookupId:404,name:"Paragraph",value:"TextBox"},{lookupId:405,name:"Single Check Box",value:"Single Check Box"}],a=[{lookupId:801,value:"1 Month"},{lookupId:802,value:"3 Months"},{lookupId:803,value:"6 Months"},{lookupId:804,value:"12 Months"}]},23661:(e,o,i)=>{i.r(o),i.d(o,{default:()=>I});var l=i(72791),n=i(95070),t=i(36638),s=i(89743),d=i(2677),a=i(43360),r=i(16856),c=i(30203),u=i(78820),p=i(61134),m=i(59434),v=i(7692),x=i(57689),h=i(3810),g=i(52268),f=i(79243),b=i(84129),j=i(80184);const I=function(){var e;const{handleSubmit:o,setValue:i,register:I}=(0,p.cI)(),[C,k]=(0,l.useState)("401"),[y,w]=(0,l.useState)([{questionId:"",question:"",options:[""],selectedType:"401",isActive:!0,isRequired:!0}]),[A,q]=(0,l.useState)(!1),{adminOnlinePrescripionForm:N,isLoading:T,isError:S,isSuccess:R}=(0,m.v9)((e=>null===e||void 0===e?void 0:e.onlinePrescriptionForm)),Z=(0,x.s0)(),F=(0,m.I0)(),L=JSON.parse(localStorage.getItem("family_doc_app"));let P=new URLSearchParams(window.location.search).get("disease");const E=()=>{w([...y,{questionId:"",question:"",options:[""],selectedType:"401",isActive:!0,isRequired:!0}])},Q=e=>{const o=[...y];o[e].options=[...y[e].options,""],w(o)},B=(e,o,i)=>{const l=[...y];l[e]={...l[e],options:l[e].options.map(((e,l)=>l===o?{...e,answerLabel:i}:e))},w(l)},M=(e,o)=>{const i=[...y];i[e]={...i[e],options:i[e].options.filter(((e,i)=>i!==o))},w(i)};function _(){const e={formId:P};F((0,f.Pw)(e))}function z(){1===(null===L||void 0===L?void 0:L.roleId)?Z(h.m.SUPERADMIN_FORMS):4===(null===L||void 0===L?void 0:L.roleId)&&Z(h.m.ADMIN_FORMS);F((0,f.LB)({Search:""}))}return(0,l.useEffect)((()=>{const e={formId:P};F((0,f.Pw)(e))}),[F,P]),(0,l.useEffect)((()=>{var e,o;P&&N&&(w([]),null===N||void 0===N||null===(e=N.data)||void 0===e||null===(o=e.formQuestionList)||void 0===o||o.map(((e,o)=>{var i;const l={title:null===N||void 0===N||null===(i=N.data)||void 0===i?void 0:i.title,questionId:e.questionId,question:e.question,options:e.formAnswersList,selectedType:e.answerTypeId.toString(),isActive:e.isActive,isRequired:e.isRequired};return w((e=>[...e,l]))})))}),[P,N]),(0,j.jsxs)(j.Fragment,{children:[(0,j.jsx)("h5",{children:"Questionnaires"}),(0,j.jsx)(n.Z,{className:"shadow-sm custom-questionnaires",children:T?(0,j.jsx)(b.Z,{}):R?(0,j.jsx)(t.Z,{onSubmit:o((function(e){var o,i,l;const n={formId:P?null===N||void 0===N||null===(o=N.data)||void 0===o?void 0:o.formId:0,title:null!==e&&void 0!==e&&e.title?null===e||void 0===e?void 0:e.title:null===N||void 0===N||null===(i=N.data)||void 0===i?void 0:i.title,isActive:!P||(null===N||void 0===N||null===(l=N.data)||void 0===l?void 0:l.isActive),formQuestionList:y.map(((e,o)=>{var i;return{questionId:null!==e&&void 0!==e&&e.questionId?null===e||void 0===e?void 0:e.questionId:0,question:null===e||void 0===e?void 0:e.question,answerTypeId:null===e||void 0===e?void 0:e.selectedType,questionOrder:o,isActive:null===e||void 0===e?void 0:e.isActive,isRequired:null===e||void 0===e?void 0:e.isRequired,answerTypeName:"401"===(null===e||void 0===e?void 0:e.selectedType)?"Radio":"402"===(null===e||void 0===e?void 0:e.selectedType)?"Checkbox":"404"===(null===e||void 0===e?void 0:e.selectedType)?"TextBox":"405"===(null===e||void 0===e?void 0:e.selectedType)?"Single Check Box":"",formId:P?null===N||void 0===N||null===(i=N.data)||void 0===i?void 0:i.formId:0,formAnswersList:e.options.map(((o,i)=>({formAnswereId:null!==o&&void 0!==o&&o.formAnswereId?null===o||void 0===o?void 0:o.formAnswereId:0,formQuestionId:null!==o&&void 0!==o&&o.formQuestionId?null===o||void 0===o?void 0:o.formQuestionId:0,answerLabel:"405"!==(null===e||void 0===e?void 0:e.selectedType)||null!==o&&void 0!==o&&o.answerLabel?null!==o&&void 0!==o&&o.answerLabel?null===o||void 0===o?void 0:o.answerLabel:"Answer Text":"Single Check Box Label"})))}}))};F((0,f.mh)({finalData:n,onCreateSuccess:z}))})),children:(0,j.jsxs)(s.Z,{className:"m-3 d-flex justify-content-center flex-column",children:[(0,j.jsxs)(d.Z,{xl:7,lg:10,xs:12,className:"mx-auto mb-3 p-0",children:[(0,j.jsxs)(t.Z.Group,{className:"px-3 pt-2 pb-4 rounded mb-3",controlId:"formTitle",style:{boxShadow:"0px 0px 24px 0px #0000000A",borderTop:"6px solid #000071"},children:[(0,j.jsxs)(t.Z.Label,{className:"mt-2 fw-bold",style:{fontSize:"1.5rem"},children:[A?"Enter ":"","Prescription Title"]}),(0,j.jsx)(t.Z.Control,{type:"text",className:"bg-transparent",placeholder:"Prescription Title",maxLength:250,name:"title",onChange:e=>i("title",e.target.value),disabled:P&&!A,defaultValue:null===N||void 0===N||null===(e=N.data)||void 0===e?void 0:e.title})]}),0===(null===y||void 0===y?void 0:y.length)?(0,j.jsx)(a.Z,{variant:"primary",type:"button",className:"Admin-Add-btn px-3 float-end",onClick:E,children:(0,j.jsx)(c.wEH,{size:24})}):P&&!A?(0,j.jsxs)(a.Z,{variant:"primary",type:"button",className:"Admin-Add-btn px-3 float-end",onClick:()=>{q(!0)},children:[(0,j.jsx)(v.Hlf,{size:24})," Edit"]}):""]}),y.map(((e,o)=>(0,j.jsxs)(d.Z,{xl:7,lg:10,xs:12,className:"p-3 rounded mx-auto mb-3",style:{boxShadow:"0px 0px 24px 0px #0000000A",borderLeft:"6px solid #F26522"},children:[(0,j.jsxs)(t.Z.Group,{className:"mb-3",children:[(!P||A)&&(0,j.jsxs)("div",{className:"d-flex justify-content-between flex-wrap align-items-center custom-col-rev mb-2",children:[(0,j.jsxs)(t.Z.Label,{className:"text-w-full mb-0",children:["Q.","".concat(o+1,".")," Enter Question"]}),(0,j.jsx)(d.Z,{xl:5,sm:6,xs:12,children:(0,j.jsx)(t.Z.Select,{"aria-label":"Select Type",onChange:e=>{((e,o)=>{k(e.target.value);const i=[...y];i[o].selectedType=e.target.value,w(i)})(e,o)},defaultValue:(null===e||void 0===e?void 0:e.selectedType)||C,disabled:P&&(null===e||void 0===e?void 0:e.questionId),className:"bg-transparent",children:g._Y.map((e=>(0,j.jsx)("option",{value:null===e||void 0===e?void 0:e.lookupId,children:e.name},null===e||void 0===e?void 0:e.lookupId)))})})]}),(0,j.jsxs)("div",{className:"405"===(null===e||void 0===e?void 0:e.selectedType)?"d-flex align-items-center justify-content-between":null,children:["405"===(null===e||void 0===e?void 0:e.selectedType)&&(0,j.jsx)(t.Z.Check,{name:"single-checkbox",type:"checkbox",className:"me-2",disabled:!0}),(0,j.jsx)(t.Z.Control,{type:"text",placeholder:"Question",maxLength:250,defaultValue:null===e||void 0===e?void 0:e.question,disabled:P&&!A,name:"questionText".concat(o),required:!0,onChange:e=>((e,o)=>{const i=[...y];i[e].question=o,w(i)})(o,e.target.value),className:"bg-transparent"})]}),(0,j.jsxs)("div",{className:"mt-2 questionnaires-option",children:["401"===(null===e||void 0===e?void 0:e.selectedType)&&(0,j.jsxs)(j.Fragment,{children:[e.options.map(((e,i)=>(0,j.jsxs)("div",{className:"d-flex align-items-center",children:[(0,j.jsx)(t.Z.Check,{label:(0,j.jsx)(j.Fragment,{children:(0,j.jsx)(t.Z.Control,{type:"text",placeholder:"Add option",className:"border-0 ms-2 bg-transparent",defaultValue:e.answerLabel,disabled:P&&!A,onChange:e=>B(o,i,e.target.value)})}),name:"group".concat(o),type:"radio",id:"radio-".concat(i),className:"d-flex align-items-center mb-1 w-100",disabled:!0}),!P&&(0,j.jsx)("span",{className:"mx-3",children:(0,j.jsx)(u.oHP,{size:18,onClick:()=>M(o,i)})})]},"radio-".concat(i)))),(!P||!(null!==e&&void 0!==e&&e.questionId))&&(0,j.jsx)("span",{className:"text-cursor-pointer text-decoration-underline",style:{color:"#3F8BFC",fontSize:"0.9em"},onClick:()=>Q(o),children:"Add another option"})]}),"404"===(null===e||void 0===e?void 0:e.selectedType)&&(0,j.jsx)(j.Fragment,{children:(0,j.jsx)(t.Z.Control,{as:"textarea",rows:3,placeholder:"Answer Text",className:"mt-2",disabled:!0})}),"402"===(null===e||void 0===e?void 0:e.selectedType)&&(0,j.jsxs)(j.Fragment,{children:[e.options.map(((e,i)=>(0,j.jsxs)("div",{className:"d-flex align-items-center",children:[(0,j.jsx)(t.Z.Check,{label:(0,j.jsx)(j.Fragment,{children:(0,j.jsx)(t.Z.Control,{type:"text",placeholder:"Add option",className:"border-0 ms-2 bg-transparent",defaultValue:e.answerLabel,disabled:P&&!A,onChange:e=>B(o,i,e.target.value)})}),name:"group".concat(o),type:"checkbox",id:"checkbox-".concat(i),className:"d-flex align-items-center mb-1 w-100",disabled:!0}),!P&&(0,j.jsx)("span",{className:"mx-3",children:(0,j.jsx)(u.oHP,{size:18,onClick:()=>M(o,i)})})]},"checkbox-".concat(i)))),(!P||!(null!==e&&void 0!==e&&e.questionId))&&(0,j.jsx)("span",{className:"text-cursor-pointer text-decoration-underline",style:{color:"#3F8BFC",fontSize:"0.9em"},onClick:()=>Q(o),children:"Add another option"})]})]})]}),(0,j.jsxs)("div",{className:"w-100 d-flex flex-wrap justify-content-end",children:[(!P||P&&A)&&(0,j.jsxs)(j.Fragment,{children:[o===y.length-1&&(0,j.jsx)("span",{style:{borderRight:"1px solid #CACACA"},children:(0,j.jsx)(c.wEH,{size:24,color:"#CACACA",className:"mx-2 text-cursor-pointer","data-toggle":"tooltip","data-placement":"top",title:"Add Question",onClick:E})}),(0,j.jsx)("span",{className:"me-2",style:{borderRight:"1px solid #CACACA"},children:(0,j.jsx)(r.I0,{size:26,color:"#CACACA",className:"mx-2 text-cursor-pointer","data-toggle":"tooltip","data-placement":"top",title:"Delete",onClick:()=>{if(P&&A&&null!==e&&void 0!==e&&e.questionId){var i;!function(e){let o={questionId:e};F((0,f.jQ)({finalData:o,getPresForm:_}))}(null===(i=e.options[o])||void 0===i?void 0:i.formQuestionId)}else(e=>{const o=[...y];o.splice(e,1),w(o)})(o)}})})]}),(0,j.jsx)(t.Z.Check,{type:"switch",id:"custom-switch-".concat(o),label:"Active",...I("isActive"),checked:!1!==(null===e||void 0===e?void 0:e.isActive),onChange:i=>{if(P&&A&&null!==e&&void 0!==e&&e.questionId){!function(e){let o={questionId:e};F((0,f.XB)({finalData:o,getPresForm:_}))}(e.questionId)}else((e,o)=>{console.log("Switch in section ".concat(e," is now ").concat(o));const i=[...y];i[e]={...i[e],isActive:o},w(i)})(o,i.target.checked)},disabled:P&&!A,className:"me-2"}),(0,j.jsx)(t.Z.Check,{type:"switch",id:"required-switch-".concat(o),label:"Required",...I("isRequired"),checked:!1!==(null===e||void 0===e?void 0:e.isRequired),onChange:i=>{if(P&&A&&null!==e&&void 0!==e&&e.questionId){!function(e){let o={questionId:e};F((0,f.xB)({finalData:o,getPresForm:_}))}(e.questionId)}else((e,o)=>{console.log("Required in section ".concat(e," is now ").concat(o));const i=[...y];i[e]={...i[e],isRequired:o},w(i)})(o,i.target.checked)},disabled:P&&!A})]})]},o))),(0!==(null===y||void 0===y?void 0:y.length)&&!P||P&&A)&&(0,j.jsx)(d.Z,{children:(0,j.jsx)(a.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold float-end",children:"Save"})})]})}):S?(0,j.jsx)("span",{className:"text-danger fst-italic",children:"Network Error"}):null})]})}}}]);
//# sourceMappingURL=3661.76171261.chunk.js.map