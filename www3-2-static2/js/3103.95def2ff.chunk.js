"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[3103],{45793:(e,l,s)=>{s.d(l,{Z:()=>t});var a=s(29086);const t=async e=>{try{const l=await a.Z.post("/digitalOcean/post",e);return null===l||void 0===l?void 0:l.data}catch(l){return l}}},60842:(e,l,s)=>{s.d(l,{Z:()=>i});s(72791);var a=s(59513),t=s.n(a),o=s(39126),n=(s(68639),s(80184));const i=e=>{let{selectedDateState:l,onChange:s,dateFormat:a="dd MMM yyyy",placeholderText:i="Date",className:d="",datePickerClassName:r="custom-field-picker px-2",useDrDateClass:c=!0,...m}=e;return console.log("disabled",m),(0,n.jsxs)("div",{className:"position-relative d-flex mb-3 ".concat(d),...m,children:[(0,n.jsx)(t(),{selected:l,onChange:s,dateFormat:a,placeholderText:i,className:"".concat(r," ").concat(c?"dr-date-w":"w-100"),disabled:null===m||void 0===m?void 0:m.disabled,minDate:null===m||void 0===m?void 0:m.mindate}),(0,n.jsx)(o.zlR,{size:18,className:"custom__date_icon"})]})}},14045:(e,l,s)=>{s.d(l,{Z:()=>o});var a=s(88135),t=s(80184);function o(e){let{children:l,...s}=e;const{handleClose:o,show:n,title:i,className:d}=s;return(0,t.jsx)("div",{children:(0,t.jsxs)(a.Z,{show:n,onHide:o,className:d,backdrop:"static",children:[(0,t.jsx)(a.Z.Header,{className:"py-3",closeButton:!0,children:(0,t.jsx)(a.Z.Title,{className:"modalTitle",children:(0,t.jsx)("span",{className:"font-weight-600",children:i})})}),(0,t.jsx)(a.Z.Body,{children:l})]})})}},13103:(e,l,s)=>{s.r(l),s.d(l,{default:()=>E});var a=s(72791),t=s(95070),o=s(89743),n=s(2677),i=s(43360),d=s(36638),r=s(53392),c=s(14045),m=s(10857),u=s(61134),p=s(72426),h=s.n(p),x=s(59434),v=s(76053),j=s(73683),f=s(78820),N=s(82962),b=s(45793),g=s(24278),y=s(65764),D=s(53473),Z=s(9085),S=s(49739),w=s(80184);const C=(0,D.J)("pk_live_51NS6LFJQrjlyogPP8wq3kFDFZOprir0PwWPucUF7VCc9WxEb2uAs6lDskTBrnzHK349ConYGh6zVQtYSpAUFfjuj00ttYrBE4D");function A(e){var l;const{handleClose:s,show:t,singleSlotData:o}=e,[n,i]=(0,a.useState)(!1),d=JSON.parse(localStorage.getItem("family_doc_app")),r=(0,x.I0)(),m=null===o||void 0===o||null===(l=o.fee)||void 0===l?void 0:l.toFixed(2),u=()=>{s(),i(!1);const e={date:h()(null===o||void 0===o?void 0:o.scheduleDate).format("YYYY-MM-DD"),month:null};r((0,N.xG)(e))};return(0,w.jsxs)(w.Fragment,{children:[(0,w.jsx)(Z.Ix,{}),(0,w.jsx)(c.Z,{handleClose:s,show:t,title:"Checkout",className:"modal-stripe",backdrop:"static",children:(0,w.jsx)(y.Elements,{stripe:C,children:(0,w.jsx)(Y,{isLoading:n,setIsLoading:i,newCoachHire:function(l){let s={...e.formData,isOneTimePayment:!0,payment:{patientId:null===d||void 0===d?void 0:d.userId,token:l,scheduleDetailId:null===o||void 0===o?void 0:o.scheduleDetailId,amount:Number(m)}};r((0,g.Pc)({finalData:s,moveToNext:u}))},singleSlotData:o})})})]})}const k=()=>{const e=function(){const e=()=>window.innerWidth<450?"16px":"18px",[l,s]=(0,a.useState)(e);return(0,a.useEffect)((()=>{const l=()=>{s(e())};return window.addEventListener("resize",l),()=>{window.removeEventListener("resize",l)}})),l}();return(0,a.useMemo)((()=>({style:{base:{fontSize:e,color:"#424770",letterSpacing:"0.025em",fontFamily:"Source Code Pro, monospace","::placeholder":{color:"#aab7c4"}},invalid:{color:"#9e2146"}}})),[e])},Y=e=>{var l;let{isLoading:s,setIsLoading:a,newCoachHire:t,singleSlotData:o}=e;const n=(0,y.useStripe)(),d=(0,y.useElements)(),c=k(),m=null===o||void 0===o||null===(l=o.fee)||void 0===l?void 0:l.toFixed(2);return(0,w.jsxs)("div",{className:"py-2 stripe",children:[(0,w.jsxs)("div",{children:[(0,w.jsx)(r.Z,{children:"Appointment Fee"}),(0,w.jsx)("input",{type:"text",value:"\u20ac".concat(m||"N/A"),disabled:!0,className:"mt-0 w-100"})]}),(0,w.jsxs)("form",{onSubmit:async e=>{if(a(!0),e.preventDefault(),n&&d)try{var l;const e=d.getElement(y.CardNumberElement),a=await n.createToken(e);var s;if(a.error)throw new Error(null===a||void 0===a||null===(s=a.error)||void 0===s?void 0:s.message);const o=null===a||void 0===a||null===(l=a.token)||void 0===l?void 0:l.id;o&&t(o)}catch(o){(0,j.P_)(null===o||void 0===o?void 0:o.message,"error"),a(!1)}},children:[(0,w.jsxs)("div",{children:["Card number",(0,w.jsx)(y.CardNumberElement,{options:c})]}),(0,w.jsxs)("div",{children:["Expiration date",(0,w.jsx)(y.CardExpiryElement,{options:c})]}),(0,w.jsxs)("div",{children:["CVC",(0,w.jsx)(y.CardCvcElement,{options:c})]}),(0,w.jsx)("div",{className:"d-flex justify-content-center mt-3",children:(0,w.jsx)(i.Z,{variant:"primary",className:"w-100 py-2 primary_bg",radius:"0px",type:"submit",disabled:s,children:s?(0,w.jsx)(S.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Confirm"})})]})]})};var I=s(57689),_=s(3810);function P(e){let{...l}=e;const{show:s,handleClose:t,formData:o,singleSlotData:n}=l,[d,r]=(0,a.useState)(!1),u=(0,I.s0)();return(0,w.jsxs)("div",{className:"AddSlot_modal",children:[(0,w.jsx)(c.Z,{className:"modal-lg",handleClose:t,show:s,children:(0,w.jsxs)("div",{className:"d-flex justify-content-center flex-column align-items-center text-center p-3",children:[(0,w.jsx)("img",{src:m.Z.BUY_PLAN,alt:"purchase plan"}),(0,w.jsx)("p",{className:"py-3",children:"We're excited to support your health journey! Please click \u2018Purchase Plan\u2019 to choose and purchase the plan that suits you best."}),(0,w.jsxs)("div",{className:"d-flex justify-content-around gap-3",children:[(0,w.jsx)(i.Z,{className:"block primary_bg",variant:"primary",type:"button",onClick:()=>{t(),r(!0)},children:"One-Time Payment"}),(0,w.jsx)(i.Z,{className:"block primary_bg",variant:"primary",type:"button",onClick:()=>u(_.m.PATIENT_PURCHASE_PLANS),children:"Purchase Plan"})]})]})}),d&&(0,w.jsx)(A,{formData:o,singleSlotData:n,handleClose:()=>r(!1),show:d})]})}function F(e){let{children:l,...s}=e;const{show:t,handleClose:p,singleSlotData:y,appointmentId:D}=s,{register:Z,handleSubmit:S,reset:C}=(0,u.cI)(),[A,k]=(0,a.useState)(!1),[Y,I]=(0,a.useState)(),[_,F]=(0,a.useState)({}),[M,T]=(0,a.useState)(),[E,V]=(0,a.useState)(),[z,L]=(0,a.useState)({isVideo:!0,isAudio:!1}),[O,G]=(0,a.useState)(!1),{remainingAptPresData:B}=(0,x.v9)((e=>null===e||void 0===e?void 0:e.doctorSchedule)),H=JSON.parse(localStorage.getItem("family_doc_app")),U=(0,x.I0)(),J=()=>{k(!1),G(!1),C({reasonForAppoinment:""}),I(null),T(null),L({isVideo:!0,isAudio:!1}),p()},R=()=>{p();const e={date:h()(null===y||void 0===y?void 0:y.scheduleDate).format("YYYY-MM-DD"),month:null};U((0,N.xG)(e))},q=async e=>{let l=e.target.files[0];if(I(l),l){const e=l.name.lastIndexOf("."),s=l.name.slice(0,e),a=l.name.slice(e+1,l.name.length);if("pdf"===a.toLowerCase()){const e=new FileReader;e.onload=async e=>{const l=e.target.result;V(!0);const t={name:s,base64:l.split(",")[1],fileExtension:"".concat(a)};(0,b.Z)(t).then((e=>{e&&(T(e),V(!1))}))},e.onerror=e=>{},e.readAsDataURL(l)}else(0,j.ZP)(l).then((e=>{V(!0);const l={name:s,base64:e,fileExtension:"".concat(a)};(0,b.Z)(l).then((e=>{e&&(T(e),V(!1))}))}))}};return(0,w.jsxs)("div",{className:"AddSlot_modal",children:[(0,w.jsx)(c.Z,{className:"modal-lg",title:D?"Reschedule Appointment":"Book Appointment",handleClose:J,show:t,children:(0,w.jsx)("div",{className:"px-2 pb-3",style:{height:"640px",overflowY:"scroll",overflowX:"hidden"},children:(0,w.jsx)(d.Z,{onSubmit:S((function(){var e,l,s;const a={scheduleId:null===y||void 0===y?void 0:y.scheduleId,appointmentDate:h()(null===y||void 0===y?void 0:y.scheduleDate).format("YYYY-MM-DD"),patientId:null===H||void 0===H?void 0:H.userId,appointmentStartTime:null===(e=(0,j.oA)((0,j.qw)(null===y||void 0===y?void 0:y.startTime),h()(null===y||void 0===y?void 0:y.scheduleDate).format("YYYY-MM-DD")))||void 0===e?void 0:e.split("Z")[0],appointmentEndTime:null===(l=(0,j.oA)((0,j.qw)(null===y||void 0===y?void 0:y.endTime),h()(null===y||void 0===y?void 0:y.scheduleDate).format("YYYY-MM-DD")))||void 0===l?void 0:l.split("Z")[0],reasonForAppoinment:null===_||void 0===_?void 0:_.reasonForAppoinment,isAudio:z.isAudio,isVideo:z.isVideo,image:null!==M&&void 0!==M&&M.keyName?null===M||void 0===M?void 0:M.keyName:null,payment:{scheduleDetailId:null===y||void 0===y?void 0:y.scheduleDetailId},isOneTimePayment:!1};null!==B&&void 0!==B&&null!==(s=B.data)&&void 0!==s&&s.appointment?U((0,g.Pc)({finalData:a,moveToNext:R})):(F(a),p(),G(!0))})),children:(0,w.jsxs)(o.Z,{children:[(0,w.jsx)(n.Z,{xl:12,children:(0,w.jsxs)(d.Z.Group,{controlId:"formDate",className:"mb-3",children:[(0,w.jsxs)(r.Z,{className:"fw-semibold fs-6",children:["Reason for Appointment",(0,w.jsx)("span",{style:{color:"#FF3A3A"},className:"fw-bold",children:"*"})]}),(0,w.jsx)(d.Z.Control,{as:"textarea",name:"reasonForAppoinment",placeholder:"Type here",style:{height:"100px"},...Z("reasonForAppoinment",{required:!_.reasonForAppoinment}),value:_.reasonForAppoinment,onChange:e=>{F({..._,[e.target.name]:e.target.value})}})]})}),console.log("formData",_),(0,w.jsxs)(n.Z,{md:6,children:[(0,w.jsxs)(d.Z.Group,{controlId:"",className:"mb-3",children:[(0,w.jsx)(r.Z,{className:"fw-semibold fs-6",children:"Date"}),(0,w.jsx)(d.Z.Control,{type:"date",placeholder:"HH:MM",className:"custom-date",defaultValue:h()(null===y||void 0===y?void 0:y.scheduleDate).format("YYYY-MM-DD"),disabled:!0,name:"appointmentDate",...Z("appointmentDate")})]}),(0,w.jsxs)(d.Z.Group,{controlId:"",className:"mb-3",children:[(0,w.jsx)(r.Z,{className:"fw-semibold fs-6",children:"Name"}),(0,w.jsx)(d.Z.Control,{type:"text",placeholder:"John Smith",className:"custom-date",name:"name",defaultValue:null===H||void 0===H?void 0:H.name,disabled:!0,...Z("name")})]})]}),(0,w.jsxs)(n.Z,{md:6,children:[(0,w.jsxs)(d.Z.Group,{controlId:"",className:"mb-3",children:[(0,w.jsx)(r.Z,{className:"fw-semibold fs-6",children:"Time"}),(0,w.jsx)(d.Z.Control,{type:"text",placeholder:"HH:MM",className:"custom-date",name:"startTime",defaultValue:"".concat(null===y||void 0===y?void 0:y.startTime," - ").concat(null===y||void 0===y?void 0:y.endTime),disabled:!0})]}),(0,w.jsxs)(d.Z.Group,{controlId:"",className:"mb-3",children:[(0,w.jsx)(r.Z,{className:"fw-semibold fs-6",children:"Email"}),(0,w.jsx)(d.Z.Control,{type:"email",placeholder:"johnsmith@gmail.com",className:"custom-date",name:"email",defaultValue:null===H||void 0===H?void 0:H.email,disabled:!0,...Z("email")})]})]}),(0,w.jsxs)(n.Z,{md:6,children:[(0,w.jsx)(d.Z.Label,{className:"fw-bold",children:"Consultation type"}),(0,w.jsxs)(d.Z.Select,{"aria-label":"Select Consultation Type",onChange:e=>{const l=e.target.value;L({isVideo:"Video"===l,isAudio:"Audio"===l})},value:z.isVideo?"Video":"Audio",children:[(0,w.jsx)("option",{value:"Video",children:"Video"}),(0,w.jsx)("option",{value:"Audio",children:"Phone"})]})]}),(0,w.jsxs)(n.Z,{xl:12,className:"upload_pic mt-3",children:[(0,w.jsx)(r.Z,{className:"fw-semibold fs-6",children:"Attachments"}),(0,w.jsxs)("div",{className:"mb-2 border py-3 rounded",children:[(0,w.jsxs)("label",{htmlFor:"patient-pic",className:"text-center w-100 pt-1",children:[(0,w.jsx)("img",{className:"mb-2 upload-icon color-dk-blue",width:"",src:m.Z.UPLOAD_ICON,alt:"location"}),(0,w.jsxs)("p",{className:"upload-text mb-1",children:["Upload a file"," ",(0,w.jsx)("span",{className:"text-black fs-6",children:" or drag and drop"})]}),(0,w.jsx)("p",{className:"upload-text_small mb-0",children:"PNG, JPG, PDF upto 5MB"})]}),(0,w.jsx)("input",{size:"small",type:"file",id:"patient-pic",name:"patient-pic",accept:"image/png, image/jpeg, application/pdf",multiple:!0,onChange:e=>{q(e)},onDrop:e=>{e.preventDefault(),q(e)},onDragOver:e=>e.preventDefault()})]}),(0,w.jsx)("div",{className:"my-3",children:(null===Y||void 0===Y?void 0:Y.name)&&(0,w.jsxs)("div",{className:"d-flex align-items-center pb-1",children:[(0,w.jsx)(v.hF6,{size:30,style:{color:"#745DED"}}),(0,w.jsx)("h6",{className:"file-name mb-0 ms-2",children:null===Y||void 0===Y?void 0:Y.name}),(0,w.jsx)("span",{className:"mx-3",children:(0,w.jsx)(f.oHP,{size:18,onClick:()=>{I(null),document.getElementById("patient-pic").value=null}})})]})}),(0,w.jsxs)("div",{className:"d-flex align-items-start",children:[(0,w.jsx)("img",{className:"me-2 mt-1 color-dk-blue",width:"",src:m.Z.INFO_ICON,alt:"location"}),(0,w.jsxs)("p",{className:"upload-text_small mb-0 fs-6",children:[" ",(0,w.jsxs)("span",{className:"text_darkGray fw-semibold",children:[" ","You can upload the following:"]})," ","Evidence for repeat prescription, reports, documents, clear photo of rash or lesion (Important Note: Please do not upload blood test results or images of intimate areas of your body)"]})]})]}),(0,w.jsx)("div",{className:"d-grid mt-4",children:D?(0,w.jsx)(i.Z,{className:"block primary_bg",variant:"primary",size:"lg",type:"submit",children:"Reschedule Appointment"}):(0,w.jsx)(i.Z,{className:"block primary_bg",variant:"primary",size:"lg",type:"submit",children:"Proceed to Pay"})})]})})})}),(0,w.jsx)(P,{formData:_,singleSlotData:y,handleClose:J,show:O})]})}var M=s(56355),T=s(60842);const E=()=>{var e;const l=(0,x.I0)(),[s,d]=(0,a.useState)(""),[r,c]=(0,a.useState)(new Date),m=(0,I.TH)(),u=null===m||void 0===m||null===(e=m.state)||void 0===e?void 0:e.appointmentId,[p,v]=(0,a.useState)(!1),[j,f]=(0,a.useState)(!1),{allSlots:b}=(0,x.v9)((e=>e.doctorSchedule)),g=JSON.parse(localStorage.getItem("family_doc_app"));const y=function(){let e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:new Date(r),l=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"en-US";return null===e||void 0===e?void 0:e.toLocaleDateString(l,{weekday:"long"})}(),D=(0,a.useMemo)((()=>r?"".concat(y," - ").concat(h()(r).format("DD-MM-YYYY")):"Select Date"),[r,y]);(0,a.useEffect)((()=>{if(r){const e={date:h()(r).format("YYYY-MM-DD"),month:null};l((0,N.xG)(e))}}),[l,r]);return(0,w.jsxs)(w.Fragment,{children:[(0,w.jsx)("h5",{children:"Available Slots"}),(0,w.jsxs)(t.Z,{className:"slotsSection mt-4",children:[(0,w.jsxs)(t.Z.Body,{children:[(0,w.jsxs)(o.Z,{className:"d-flex justify-content-between align-items-center mb-4",children:[(0,w.jsx)(n.Z,{xl:2,lg:4,md:4,sm:6,children:(0,w.jsx)(T.Z,{selectedDateState:r,onChange:e=>c(e),useDrDateClass:!1,dateFormat:"dd/MM/yyyy",placeholderText:"day/month/year",mindate:new Date})}),(0,w.jsx)(n.Z,{md:4,lg:4,className:"text-center",children:(0,w.jsx)("h5",{className:"text-black fw-bold mb-0",children:D})}),(0,w.jsx)(n.Z,{md:4,sm:4,children:(0,w.jsxs)("div",{className:"d-flex justify-content-end radioGroup",children:[(0,w.jsxs)("div",{className:"d-flex align-items-center me-sm-4 me-2",children:[(0,w.jsx)("span",{className:"bookedSlot rounded-circle me-2",children:(0,w.jsx)(M.gbA,{color:"#ff6060",size:"22"})}),(0,w.jsx)("span",{children:"Booked Slots"})]}),(0,w.jsxs)("div",{className:"d-flex align-items-center",children:[(0,w.jsx)("span",{className:"availableSlot rounded-circle me-2",children:(0,w.jsx)(M.gbA,{color:"#81d363",size:"22"})}),(0,w.jsx)("span",{children:"Available Slots"})]})]})})]}),(0,w.jsx)("div",{className:"doctor_Details",children:(0,w.jsx)("div",{className:"slotContainer mt-4 pt-3",children:null!==b&&(null===b||void 0===b?void 0:b.length)>0?null===b||void 0===b?void 0:b.map((e=>(0,w.jsxs)(i.Z,{className:"slot_btn".concat(null!==e&&void 0!==e&&e.isBooked?" booked":""),onClick:()=>(d(e),void v(!0)),children:[null===e||void 0===e?void 0:e.startTime," - ",null===e||void 0===e?void 0:e.endTime]},null===e||void 0===e?void 0:e.startTime))):(0,w.jsx)("p",{className:"text-center",children:"No Slot Available"})})}),(0,w.jsx)("div",{className:"float-right mt-4",children:(0,w.jsx)(i.Z,{onClick:()=>{f(!0);const e={patientId:null===g||void 0===g?void 0:g.userId};l((0,N.lr)(e))},className:"btn-primary px-5 primary_bg",disabled:!0===(null===s||void 0===s?void 0:s.isBooked)||!s,children:"Continue"})})]}),(0,w.jsx)(F,{show:j,handleClose:()=>f(!1),singleSlotData:s,appointmentId:u})]})]})}}}]);
//# sourceMappingURL=3103.95def2ff.chunk.js.map