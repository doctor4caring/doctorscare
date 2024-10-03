"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[3661],{52268:(e,o,t)=>{t.d(o,{Tf:()=>l,_Y:()=>a,bA:()=>n,lt:()=>i,sP:()=>s});const n=[{lookupId:6,value:"Nurse"},{lookupId:7,value:"Receptionist"}],s=[{lookupId:101,value:"Male"},{lookupId:102,value:"Female"},{lookupId:103,value:"Other"}],l={Destroyed:"destroyed",Error:"error",Incoming:"incoming",Registered:"registered",Registering:"registering",TokenWillExpire:"tokenWillExpire",Unregistered:"unregistered"},i={Connected:"connected",Accept:"accept",Audio:"audio",Cancel:"cancel",Disconnect:"disconnect",Error:"error",Mute:"mute",Reconnected:"reconnected",Reconnecting:"reconnecting",Reject:"reject",Ringing:"ringing",Sample:"sample",Volume:"volume",WarningCleared:"warning-cleared",Warning:"warning"},a=[{lookupId:401,name:"Multiple Choice",value:"Radio"},{lookupId:402,name:"Checkbox",value:"Checkbox"},{lookupId:404,name:"Paragraph",value:"TextBox"}]},23661:(e,o,t)=>{t.r(o),t.d(o,{default:()=>f});var n=t(72791),s=t(95070),l=t(36638),i=t(89743),a=t(2677),c=t(43360),r=t(16856),d=t(30203),p=t(78820),m=t(61134),u=t(59434),x=t(3810),h=t(79243),g=t(52268),v=t(57689),j=t(80184);const f=function(){var e;const{handleSubmit:o,register:t}=(0,m.cI)(),[f,C]=(0,n.useState)("401"),[b,y]=(0,n.useState)([{question:"",options:[""],selectedType:"401"}]),{adminOnlinePrescripionForm:A}=(0,u.v9)((e=>null===e||void 0===e?void 0:e.onlinePrescriptionForm));console.log("adminOnlinePrescripionForm",A),console.log("sections",b);const w=(0,v.s0)(),k=(0,u.I0)(),N=JSON.parse(localStorage.getItem("family_doc_app"));let I=new URLSearchParams(window.location.search).get("disease");const T=()=>{y([...b,{question:"",options:[""],selectedType:"401"}])},S=e=>{const o=[...b];o[e].options=[...b[e].options,""],y(o)},Z=(e,o,t)=>{const n=[...b];n[e].options[o]=t,y(n)},F=(e,o)=>{const t=[...b];t[e].options.splice(o,1),y(t)};function R(){1===(null===N||void 0===N?void 0:N.roleId)?w(x.m.SUPERADMIN_FORMS):4===(null===N||void 0===N?void 0:N.roleId)&&w(x.m.ADMIN_FORMS);k((0,h.LB)({Search:""}))}return(0,n.useEffect)((()=>{const e={formId:I};k((0,h.Pw)(e))}),[k,I]),(0,n.useEffect)((()=>{var e,o;I&&A&&(null===A||void 0===A||null===(e=A.data)||void 0===e||null===(o=e.formQuestionList)||void 0===o||o.map(((e,o)=>{const t={question:e.question,options:e.formAnswersList,selectedType:e.answerTypeId.toString()};return y((e=>[...e,t]))})))}),[I,A]),(0,j.jsxs)(j.Fragment,{children:[(0,j.jsx)("h5",{children:"Questionnaires"}),(0,j.jsx)(s.Z,{className:"shadow-sm custom-questionnaires",children:(0,j.jsx)(l.Z,{onSubmit:o((function(e){const o={formId:0,title:null===e||void 0===e?void 0:e.title,isActive:!0,formQuestionList:b.map(((e,o)=>({questionId:0,question:e.question,answerTypeId:null===e||void 0===e?void 0:e.selectedType,answerTypeName:"401"===(null===e||void 0===e?void 0:e.selectedType)?"Radio":"402"===(null===e||void 0===e?void 0:e.selectedType)?"Checkbox":"404"===(null===e||void 0===e?void 0:e.selectedType)?"TextBox":"",formId:0,formAnswersList:e.options.map(((e,o)=>({formAnswereId:0,formQuestionId:0,answerLabel:e||"Answer Text"})))})))};k((0,h.mh)({finalData:o,onCreateSuccess:R}))})),children:(0,j.jsxs)(i.Z,{className:"m-3 d-flex justify-content-center flex-column",children:[(0,j.jsxs)(a.Z,{xl:7,lg:10,xs:12,className:"mx-auto mb-3 p-0",children:[(0,j.jsxs)(l.Z.Group,{className:"px-3 pt-2 pb-4 rounded mb-3",controlId:"formTitle",style:{boxShadow:"0px 0px 24px 0px #0000000A",borderTop:"6px solid #6045EB"},children:[(0,j.jsx)(l.Z.Label,{className:"mt-2",children:"Enter Form Title"}),(0,j.jsx)(l.Z.Control,{type:"text",placeholder:"Form Title",maxLength:250,...t("title",{required:!0}),disabled:I,defaultValue:I?null===A||void 0===A||null===(e=A.data)||void 0===e?void 0:e.title:""})]}),0===(null===b||void 0===b?void 0:b.length)&&(0,j.jsx)(c.Z,{variant:"primary",type:"button",className:"Admin-Add-btn px-3 float-end",children:(0,j.jsx)(d.wEH,{size:24,onClick:T})})]}),b.map(((e,o)=>(0,j.jsxs)(a.Z,{xl:7,lg:10,xs:12,className:"p-3 rounded mx-auto mb-3",style:{boxShadow:"0px 0px 24px 0px #0000000A",borderLeft:"6px solid #3F8BFC"},children:[(0,j.jsxs)(l.Z.Group,{className:"mb-3",controlId:"formQuestion".concat(o),children:[(0,j.jsxs)("div",{className:"d-flex justify-content-between flex-wrap align-items-center custom-col-rev mb-2",children:[(0,j.jsx)(l.Z.Label,{className:"text-w-full",children:"Enter Question"}),(0,j.jsx)(a.Z,{xl:5,sm:6,xs:12,children:(0,j.jsx)(l.Z.Select,{"aria-label":"Select Type",onChange:e=>{((e,o)=>{C(e.target.value);const t=[...b];t[o].selectedType=e.target.value,y(t)})(e,o)},defaultValue:e.selectedType||f,children:g._Y.map((e=>(0,j.jsx)("option",{value:null===e||void 0===e?void 0:e.lookupId,children:e.name})))})})]}),(0,j.jsx)(l.Z.Control,{type:"text",placeholder:"Question",required:!0,maxLength:250,value:e.question,onChange:e=>((e,o)=>{const t=[...b];t[e].question=o,y(t)})(o,e.target.value)}),(0,j.jsxs)("div",{className:"mt-2 questionnaires-option",children:["401"===e.selectedType&&(0,j.jsxs)(j.Fragment,{children:[e.options.map(((e,t)=>(0,j.jsxs)("div",{className:"d-flex align-items-center",children:[(0,j.jsx)(l.Z.Check,{label:(0,j.jsx)(j.Fragment,{children:(0,j.jsx)(l.Z.Control,{type:"text",placeholder:"Add option",className:"border-0 ms-2",value:e,onChange:e=>Z(o,t,e.target.value)})}),name:"group".concat(o),type:"radio",id:"radio-".concat(t),className:"d-flex align-items-center mb-1 w-100"}),(0,j.jsx)("span",{className:"mx-3",children:(0,j.jsx)(p.oHP,{size:18,onClick:()=>F(o,t)})})]},"radio-".concat(t)))),(0,j.jsx)("span",{className:"text-cursor-pointer text-decoration-underline",style:{color:"#3F8BFC",fontSize:"0.9em"},onClick:()=>S(o),children:"Add another option"})]}),"404"===e.selectedType&&(0,j.jsx)(j.Fragment,{children:(0,j.jsx)(l.Z.Control,{as:"textarea",rows:3,placeholder:"Answer Text",className:"mt-2",disabled:!0})}),"402"===e.selectedType&&(0,j.jsxs)(j.Fragment,{children:[e.options.map(((e,t)=>(0,j.jsxs)("div",{className:"d-flex align-items-center",children:[(0,j.jsx)(l.Z.Check,{label:(0,j.jsx)(j.Fragment,{children:(0,j.jsx)(l.Z.Control,{type:"text",placeholder:"Add option",className:"border-0 ms-2",value:e,onChange:e=>Z(o,t,e.target.value)})}),name:"group".concat(o),type:"checkbox",id:"checkbox-".concat(t),className:"d-flex align-items-center mb-1 w-100"}),(0,j.jsx)("span",{className:"mx-3",children:(0,j.jsx)(p.oHP,{size:18,onClick:()=>F(o,t)})})]},"checkbox-".concat(t)))),(0,j.jsx)("span",{className:"text-cursor-pointer text-decoration-underline",style:{color:"#3F8BFC",fontSize:"0.9em"},onClick:()=>S(o),children:"Add another option"})]})]})]}),(0,j.jsxs)("div",{className:"w-100 d-flex flex-wrap justify-content-end",children:[(0,j.jsx)("span",{style:{borderRight:"1px solid #CACACA"},children:(0,j.jsx)(d.wEH,{size:24,color:"#CACACA",className:"mx-2 text-cursor-pointer","data-toggle":"tooltip","data-placement":"top",title:"Add Question",onClick:T})}),(0,j.jsx)("span",{className:"me-2",style:{borderRight:"1px solid #CACACA"},children:(0,j.jsx)(r.I0,{size:26,color:"#CACACA",className:"mx-2 text-cursor-pointer","data-toggle":"tooltip","data-placement":"top",title:"Delete",onClick:()=>(e=>{const o=[...b];o.splice(e,1),y(o)})(o)})}),(0,j.jsx)(l.Z.Check,{type:"switch",id:"custom-switch-".concat(o),label:"Active",...t("isActive"),defaultChecked:!0,onChange:e=>{((e,o)=>{console.log("Switch in section ".concat(e," is now ").concat(o))})(o,e.target.checked)}})]})]},o))),0!==(null===b||void 0===b?void 0:b.length)&&(0,j.jsx)(a.Z,{children:(0,j.jsx)(c.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold float-end",children:"Save"})})]})})})]})}}}]);
//# sourceMappingURL=3661.dc45fd9e.chunk.js.map