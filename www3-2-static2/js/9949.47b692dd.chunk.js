"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[9949],{52268:(e,n,i)=>{i.d(n,{Tf:()=>o,_Y:()=>l,bA:()=>t,df:()=>d,lt:()=>s,sP:()=>a});const t=[{lookupId:6,value:"Nurse"},{lookupId:7,value:"Receptionist"}],a=[{lookupId:101,value:"Male"},{lookupId:102,value:"Female"},{lookupId:103,value:"Other"}],o={Destroyed:"destroyed",Error:"error",Incoming:"incoming",Registered:"registered",Registering:"registering",TokenWillExpire:"tokenWillExpire",Unregistered:"unregistered"},s={Connected:"connected",Accept:"accept",Audio:"audio",Cancel:"cancel",Disconnect:"disconnect",Error:"error",Mute:"mute",Reconnected:"reconnected",Reconnecting:"reconnecting",Reject:"reject",Ringing:"ringing",Sample:"sample",Volume:"volume",WarningCleared:"warning-cleared",Warning:"warning"},l=[{lookupId:401,name:"Multiple Choice",value:"Radio"},{lookupId:402,name:"Checkbox",value:"Checkbox"},{lookupId:404,name:"Paragraph",value:"TextBox"},{lookupId:405,name:"Single Check Box",value:"Single Check Box"}],d=[{lookupId:801,value:"1 Month"},{lookupId:802,value:"3 Months"},{lookupId:803,value:"6 Months"},{lookupId:804,value:"12 Months"}]},43426:(e,n,i)=>{i.d(n,{Z:()=>l});i(72791);var t=i(95070),a=i(72426),o=i.n(a),s=i(80184);function l(e){const{name:n,genderInfo:i,gender:a,dobInfo:l,dob:d,professionInfo:c,profession:r,currentLocationInfo:h,currentLocation:u,patientLocalGPInfo:m,patientLocalGP:p,emailInfo:v,email:x,phoneInfo:j,phone:y,specialityInfo:g,speciality:f,pharmacyInfo:N,pharmacy:b,locationInfo:D,location:I,image:S}=e;return(0,s.jsx)(t.Z,{className:"generic-card border__radius-10",children:(0,s.jsxs)(t.Z.Body,{className:"p-0 main-personalprofile position-relative",children:[(0,s.jsx)("div",{className:"ds-top"}),(0,s.jsxs)("div",{className:"position-relative",children:[(0,s.jsx)("div",{className:"avatar-holder upload_pic profile_upload profileContent",children:(0,s.jsx)("img",{src:S||"https://ui-avatars.com/api/?name=".concat("".concat(n),"&background=000071&color=fff"),alt:"Patient"})}),(0,s.jsx)("div",{className:"name",children:n||"N/A"})]}),(0,s.jsxs)("div",{className:"mx-4 card-content patient-personal-details",children:[i&&(0,s.jsxs)(s.Fragment,{children:[" ",(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between pt-3",children:[(0,s.jsx)("p",{children:"Gender"}),(0,s.jsx)("p",{children:a||"N/A"})]}),(0,s.jsx)("hr",{})]}),l&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"D.O.B"}),(0,s.jsx)("p",{children:o()(d).format("MM/DD/YYYY")})]}),(0,s.jsx)("hr",{})]}),D&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Location"}),(0,s.jsx)("p",{children:I||"N/A"})]}),(0,s.jsx)("hr",{})]}),c&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Profession/Occupation:"}),(0,s.jsx)("p",{children:r||"N/A"})]}),(0,s.jsx)("hr",{})]}),h&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Current Location"}),(0,s.jsx)("p",{children:u||"N/A"})]}),(0,s.jsx)("hr",{})]}),m&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Patient Local GP"}),(0,s.jsx)("p",{children:p||"N/A"})]}),(0,s.jsx)("hr",{})]}),v&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Email"}),(0,s.jsx)("p",{children:x||"N/A"})]}),(0,s.jsx)("hr",{})]}),N&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Pharmacy"}),(0,s.jsx)("p",{children:b||"N/A"})]}),(0,s.jsx)("hr",{})]}),j&&(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Phone"}),(0,s.jsx)("p",{children:y||"N/A"})]}),(0,s.jsx)("hr",{})]}),g&&(0,s.jsxs)("span",{className:"d-flex flex-wrap justify-content-between",children:[(0,s.jsx)("p",{children:"Speciality"}),(0,s.jsx)("p",{children:f||"N/A"})]})]})]})})}},14212:(e,n,i)=>{i.r(n),i.d(n,{default:()=>W});var t=i(72791),a=i(89743),o=i(2677),s=i(95070),l=i(19485),d=i(61734),c=i(69764),r=i(59434),h=i(43360),u=i(88135),m=i(58617),p=i(56355),v=i(84373),x=i(49739),j=i(20240),y=i(78820),g=i(80184);const f=function(e){const{showEndModal:n,handleCloseEndModal:i,discounthandlerEnd:t}=e;return(0,g.jsx)("div",{children:(0,g.jsxs)(u.Z,{show:n,onHide:i,size:"lg","aria-labelledby":"contained-modal-title-vcenter",centered:!0,className:"appointment-modal",children:[(0,g.jsx)(u.Z.Header,{closeButton:!0}),(0,g.jsxs)(u.Z.Body,{children:[(0,g.jsx)("div",{className:"d-flex justify-content-center ",children:(0,g.jsx)("span",{className:"stethoscope-icon",children:(0,g.jsx)(p.K7y,{size:34})})}),(0,g.jsxs)("div",{className:"my-3",children:[(0,g.jsx)("h4",{className:"text-center w-50 mx-auto my-0",style:{fontWeight:600},children:"You are about to end this appointment"}),(0,g.jsx)("p",{className:"text-center mt-3 mb-4",children:"Note: If you end this appointment, you will not be able to reconnect"})]}),(0,g.jsx)("span",{className:"d-flex justify-content-center mt-2 mb-5",children:(0,g.jsx)(h.Z,{className:"end-apt-btn",onClick:()=>(t(),void i()),children:"End Appointment"})})]})]})})};class N extends t.Component{constructor(e){var n,i;super(e),this.setAudio=e=>{this.setState({audio:e})},this.setVideo=e=>{this.setState({video:e})},this.setShowEndModal=e=>{this.setState({showEndModal:e})},this.changeVideoSource=e=>{"camera"!==this.state.videoSource?this.setState({videoSource:"camera"}):this.setState({videoSource:"screen"})},this.onError=e=>{this.setState({error:"Failed to publish: ".concat(e.message)})},this.discounthandler=async()=>{var e,n,i,t,a;await(null===(e=this.props)||void 0===e||null===(n=e.otSession)||void 0===n||null===(i=n.current)||void 0===i||null===(t=i.sessionHelper)||void 0===t||null===(a=t.session)||void 0===a?void 0:a.destroy())},this.discounthandlerEnd=async()=>{await this.props.otSession.current.sessionHelper.session.destroy()},this.state={error:null,audio:!0,video:(null===(n=this.props.videoCallData)||void 0===n||!n.isAudio)&&(null!==(i=this.props.videoCallData)&&void 0!==i&&i.isVideo,!0),showEndModal:!1,videoSource:"camera"}}render(){return(0,g.jsxs)("div",{className:"videocall publisher",children:[(0,g.jsxs)("div",{className:"d-flex justify-content-end me-3 position-relative publisher-video-box",children:[(0,g.jsx)("div",{children:(0,g.jsx)(j.VI,{properties:{publishAudio:this.state.audio,publishVideo:this.state.video,videoSource:"screen"===this.state.videoSource?"screen":void 0}})}),(0,g.jsxs)("div",{className:"position-absolute d-flex justify-content-between align-items-center",style:{right:"6.5rem",top:"8.8rem",width:"fit-content"},children:[(0,g.jsx)("div",{className:"publisher-name",children:(0,g.jsx)("h6",{className:"text-white mb-0",children:this.props.user.name})}),!1===this.state.audio&&(0,g.jsx)("div",{className:"publisher-mute",children:(0,g.jsx)(y.Q4c,{className:"strem--controls-icon cursor m-2 text-white",size:20,onClick:()=>this.setAudio(!1)})})]})]}),(0,g.jsx)("div",{className:"row pt-5 px-2",children:(0,g.jsx)("div",{className:"randox-div",children:(0,g.jsx)("div",{className:"position_set",children:(0,g.jsxs)("div",{className:"d-flex justify-content-between streem-control-container w-100",children:[(0,g.jsxs)("div",{children:[this.state.audio?(0,g.jsx)("span",{className:"botton-icons me-4",children:(0,g.jsx)(y.aRZ,{className:"strem--controls-icon cursor m-2",size:24,onClick:()=>this.setAudio(!1)})}):(0,g.jsx)("span",{className:"botton-icons me-4",children:(0,g.jsx)(y.Q4c,{className:"strem--controls-icon cursor m-2",size:24,onClick:()=>this.setAudio(!0)})}),this.state.video?(0,g.jsx)("span",{className:"botton-icons me-4",children:(0,g.jsx)(p.KoQ,{className:"strem--controls-icon cursor m-2",size:24,onClick:()=>this.setVideo(!1)})}):(0,g.jsx)("span",{className:"botton-icons me-4",children:(0,g.jsx)(p.uCi,{className:"strem--controls-icon cursor m-2",size:24,onClick:()=>this.setVideo(!0)})})]}),(0,g.jsx)("span",{className:"appointment-last-span",children:this.props.user&&this.props.user&&this.props.user.token&&"Patient"===this.props.user.role&&(0,g.jsx)("div",{className:"end_call",children:(0,g.jsx)(h.Z,{style:{background:"#FD2121",border:"none"},onClick:()=>this.setShowEndModal(!0),className:"px-4",children:"End Appointment"})})})]})})})}),(0,g.jsx)(f,{showEndModal:this.state.showEndModal,handleCloseEndModal:()=>this.setShowEndModal(!1),discounthandlerEnd:async()=>{this.discounthandlerEnd()},slotDescription:this.props.slotDescription})]})}}const b=N;class D extends t.Component{constructor(e){super(e),this.setAudio=e=>{this.setState({audio:e})},this.setVideo=e=>{this.setState({video:e})},this.onError=e=>{this.setState({error:"Failed to subscribe: ".concat(e.message)})},this.state={error:null,audio:!0,video:!0}}render(){return(0,g.jsx)("div",{className:"subscriber",children:(0,g.jsxs)("div",{className:"position-relative",children:[(0,g.jsx)("div",{children:(0,g.jsx)(j.dR,{properties:{subscribeToAudio:this.state.audio,subscribeToVideo:this.state.video}})}),(0,g.jsx)("div",{className:"publisher__name-section",children:(0,g.jsx)("div",{className:"publisher-name",children:(0,g.jsx)("h6",{className:"text-white mb-0",children:this.props.slotDescription.patientName})})})]})})}}const I=D;class S extends t.Component{constructor(e){super(e),this.onSignalRecieve=e=>{console.log("onSignalReceive => ",JSON.parse(e.data))},this.onError=e=>{this.setState({error:"Failed to connect: ".concat(e.message)})},this.otSession=t.createRef(),this.state={error:null,connected:!1},this.sessionEvents={sessionConnected:()=>{this.setState({connected:!0})},sessionDisconnected:()=>{this.setState({connected:!1})}}}render(){var e,n,i,t,a,o,s,l,d,c,r,h,u;return(0,g.jsxs)(j.Bp,{ref:null===this||void 0===this?void 0:this.otSession,apiKey:"47602941",sessionId:null===this||void 0===this||null===(e=this.props)||void 0===e||null===(n=e.videoCallData)||void 0===n?void 0:n.vonageSessionId,token:null===this||void 0===this||null===(i=this.props)||void 0===i||null===(t=i.videoCallData)||void 0===t?void 0:t.token,eventHandlers:null===this||void 0===this?void 0:this.sessionEvents,onError:this.onError,children:[this.state.error?(0,g.jsx)("div",{id:"error",children:this.state.error}):null,(0,g.jsxs)("div",{className:"position-relative w-100",children:[0===(null===(a=this.otSession)||void 0===a||null===(o=a.current)||void 0===o||null===(s=o.state)||void 0===s||null===(l=s.streams)||void 0===l?void 0:l.length)&&(0,g.jsx)(P,{show:null===(d=this.otSession)||void 0===d||null===(c=d.current)||void 0===c||null===(r=c.state)||void 0===r||null===(h=r.streams)||void 0===h?void 0:h.length,session:this.otSession}),(0,g.jsx)(j.e_,{children:(0,g.jsx)(I,{slotDescription:this.props.slotDescription})}),(0,g.jsx)(b,{user:this.props.user,setShowEndModal:this.props.setShowEndModal,otSession:this.otSession,slotDescription:this.props.slotDescription,videoCallData:null===(u=this.props)||void 0===u?void 0:u.videoCallData})]})]})}}const w=(0,j.kK)(S);function P(e){var n,i,a;let{session:o}=e;const[s,l]=(0,t.useState)();return(0,t.useEffect)((()=>{var e,n,i;l(null===(e=o.current)||void 0===e||null===(n=e.state)||void 0===n||null===(i=n.streams)||void 0===i?void 0:i.length)}),[null===(n=o.current)||void 0===n||null===(i=n.state)||void 0===i||null===(a=i.streams)||void 0===a?void 0:a.length]),(0,g.jsx)("div",{className:"video-appointment abcd ".concat(0===s?"d-block":"d-none"),children:(0,g.jsxs)("div",{className:"d-flex align-items-center justify-content-center h-100",children:[(0,g.jsx)(m.HQH,{className:"exclamation-icon me-2 mb-3",size:28}),(0,g.jsx)("p",{className:"not-joined-text m-0",style:{fontWeight:600},children:"The Patient has not yet joined the appointment"})]})})}var Z=i(24278),C=i(21334);function k(){const e=JSON.parse(localStorage.getItem("slotDescription")),n=(0,r.I0)(),i=JSON.parse(localStorage.getItem("family_doc_app")),[a,o]=(0,t.useState)(1),[s,l]=(0,t.useState)(!1),[d,c]=(0,t.useState)(!1),{videoCallData:j,isLoading:y}=(0,r.v9)((e=>null===e||void 0===e?void 0:e.vonageData)),f=()=>{const i={appointmentId:null===e||void 0===e?void 0:e.appointmentId};n((0,Z.MM)(i))};return(0,g.jsxs)(g.Fragment,{children:[1===a&&(0,g.jsxs)("div",{className:"video-appointment",children:[(0,g.jsxs)("div",{className:"d-flex align-items-center justify-content-center h-100",children:[(0,g.jsx)(m.HQH,{className:"exclamation-icon me-2 mb-3",size:28}),(0,g.jsx)("p",{className:"not-joined-text m-0",style:{fontWeight:600},children:"The patient has not yet joined the appointment"})]}),(0,g.jsx)("div",{className:"px-2 my-4 d-flex flex-wrap justify-content-end align-items-center",children:(0,g.jsx)(h.Z,{style:{background:"#000071"},onClick:()=>l(!0),className:"px-4",children:"Start Appointment"})}),(0,g.jsxs)(u.Z,{show:s,onHide:()=>{l(!1)},size:"lg","aria-labelledby":"contained-modal-title-vcenter",centered:!0,className:"appointment-modal custom-modal-size",children:[(0,g.jsx)(u.Z.Header,{closeButton:!0}),(0,g.jsxs)(u.Z.Body,{children:[(0,g.jsx)("div",{className:"d-flex justify-content-center",children:(0,g.jsx)("span",{className:"stethoscope-icon",children:(0,g.jsx)(p.K7y,{size:34})})}),(0,g.jsx)("div",{className:"my-3",children:(0,g.jsx)("h4",{className:"text-center w-50 mx-auto my-0",children:"You are about to start this appointment"})}),(0,g.jsx)("span",{className:"d-flex justify-content-center",children:(0,g.jsx)(h.Z,{className:"start-apt-btn ".concat(y&&"disabled"),onClick:()=>(()=>{const i={sessionId:null===e||void 0===e?void 0:e.vonageSessionId};n((0,C.sR)({finalData:i,moveToNext:f})),o(2)})(),children:!0===y?(0,g.jsx)(x.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Start"})}),(0,g.jsxs)("span",{className:"d-flex justify-content-center align-items-center mb-3 mt-4",style:{cursor:"pointer"},children:[(0,g.jsx)(v.PjY,{size:25}),(0,g.jsx)("p",{className:"mb-0",style:{fontWeight:500,fontSize:"18px"},children:"Go Back"})]})]})]})]}),2===a&&!1===y&&(0,g.jsx)("div",{className:"appointment-started",children:(0,g.jsx)("span",{children:(0,g.jsx)(w,{videoCallData:j,user:i,setShowEndModal:c,slotDescription:e})})})]})}var E=i(43426),A=i(95985),L=i(82573),T=i(76637),H=i(36638),F=i(61134),M=i(95431),R=(i(10215),i(9897)),_=i(52268);const O=()=>{var e;const{register:n}=(0,F.cI)(),[i,a]=(0,t.useState)(_.Tf.Unregistered),[o,s]=(0,t.useState)(null),[l,d]=(0,t.useState)(null),{videoCallData:c}=((0,r.I0)(),(0,r.v9)((e=>(null===e||void 0===e?void 0:e.vonageData)||{}))),{patientAppointedDetail:u}=(0,r.v9)((e=>e.appointment));function m(e){a(_.Tf.Registering),console.log("Initializing a new device",i);let n=new M.AS(null===e||void 0===e?void 0:e.twilioToken,{logLevel:1,codecPreferences:["opus","pcmu"]});!function(e){e.on("registered",(function(){console.log("The device is ready to make and receive incoming calls."),a(_.Tf.Registered)})),e.on("registering",(function(){a(_.Tf.Registering)})),e.on("error",(function(e){console.log("Twilio.Device Error: "+e.message),a(_.Tf.Error)})),e.audio.on("deviceChange",(function(){console.log("device Change")}))}(n),n.register(),async function(e,n){var i;const t=null===n||void 0===n?void 0:n.callingDeviceIdentity;var a={To:null===u||void 0===u||null===(i=u.detailDTO)||void 0===i?void 0:i.phoneNumber,callingDeviceIdentity:t};if(e){console.log("Attempting to call ".concat(a.To," ..."));const n=await e.connect({params:a});d(n),n&&(s(_.lt.Connected),console.log("setCallStateConnected",o)),console.log("Connection successful:",s),n.on("accept",(function(){console.log("'accepted' means the call has finished connecting and the state is now 'open'"),s(_.lt.Accept)})),n.on("ringing",(function(){console.log("Ringing ..."),s(_.lt.Ringing)})),n.on("disconnect",(function(){console.log("Call Disconnected"),s(_.lt.Disconnect,(()=>{console.log("callState",o)}))})),n.on("cancel",(function(){console.log("Call Cancelled"),s(_.lt.Cancel)}))}else console.log("Unable to make call.")}(n,e)}function p(){console.log("Requesting Access Token...");m({twilioToken:null===c||void 0===c?void 0:c.twilioToken,callingDeviceIdentity:null===c||void 0===c?void 0:c.twilioIdentity})}return(0,g.jsxs)(g.Fragment,{children:[(0,g.jsx)("div",{className:"d-flex justify-content-center",children:(0,g.jsx)("img",{src:R.Z.TWILIO_LOGO,alt:"Twilio Logo",width:120,height:"auto",className:"".concat("disconnect"!==o&&"unregistered"!==i&&"error"!==i?"rotate-img":"")})}),(0,g.jsxs)(H.Z.Group,{className:"mb-2",controlId:"numberField",children:[(0,g.jsx)(H.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,g.jsx)(H.Z.Control,{type:"text",placeholder:"+1 530 673 3342",size:"md",...n("toNumber",{required:!0}),defaultValue:null===u||void 0===u||null===(e=u.detailDTO)||void 0===e?void 0:e.phoneNumber,disabled:!0,className:"custom-field-picker bg-transparent"})]}),"error"===i?(0,g.jsx)("p",{className:"mb-0",style:{fontSize:"14px",color:"#E31E27"},children:"Unable to Connect Server"}):"",(0,g.jsx)("div",{className:"d-flex",children:"ringing"===o?(0,g.jsx)("p",{className:"mb-0 mx-auto my-0",style:{color:"#44BC19"},children:"Ringing ..."}):"registering"===i?(0,g.jsx)("p",{className:"mb-0 mx-auto my-0",style:{color:"#FFB400"},children:"Registring ..."}):(0,g.jsx)(h.Z,{style:{background:"transparent",border:"none",color:"#E31E27"},disabled:!c,className:"fw-bold px-4 mx-auto my-0 cursor-pointer",onClick:"unregistered"===i||"disconnect"===o||"error"===i?p:function(){l&&(console.log("Hanging up ...",l),l.disconnect())},children:"unregistered"===i||"disconnect"===o||"error"===i?"Switch to Phone Call":"Hang Up"})})]})};var z=i(38713),B=i(17425),V=i(63521),G=i(39126);function K(){var e,n,i,s,l,d,c,u,m,p,v,x,j,y,f,N,b,D,I,S,w,P,Z,C,k,E,A;const[T,M]=(0,t.useState)(""),[R,_]=(0,t.useState)(!1),[O,K]=(0,t.useState)(),[W,U]=(0,t.useState)({}),[Y,J]=(0,t.useState)(!1),[Q,X]=(0,t.useState)(),{patientPharmacy:q}=(0,r.v9)((e=>e||{})),{patientAppointedDetail:$}=(0,r.v9)((e=>e.appointment)),{register:ee,handleSubmit:ne,setValue:ie,reset:te}=(0,F.cI)(),ae=JSON.parse(localStorage.getItem("slotDescription")),oe=(0,r.I0)(),se=()=>{const e={PatientId:null===ae||void 0===ae?void 0:ae.patientId};oe((0,L.jX)(e)),_(!1)};const le=()=>{const e={patientId:null===ae||void 0===ae?void 0:ae.patientId};oe((0,L.jX)(e)),_(!1),te()};return(0,g.jsxs)(g.Fragment,{children:[(0,g.jsx)(H.Z,{onSubmit:ne((function(e){var n,i,t,a,o,s,l;const d={pharmacyId:O||(null===q||void 0===q||null===(n=q.patientPharmacyData)||void 0===n?void 0:n.pharmacyId)||0,pharmacyEmail:null===e||void 0===e?void 0:e.pharmacyEmail,pharmacyName:Q||(null===q||void 0===q||null===(i=q.patientPharmacyData)||void 0===i?void 0:i.pharmacyName)||"",pharmacyLocation:(null===e||void 0===e?void 0:e.pharmacyLocation)||(null===q||void 0===q||null===(t=q.patientPharmacyData)||void 0===t?void 0:t.pharmacyLocation)||"",country:(null===e||void 0===e?void 0:e.country)||(null===q||void 0===q||null===(a=q.patientPharmacyData)||void 0===a?void 0:a.country)||"",ig_xcord:"",ig_ycord:"",userId:null===$||void 0===$||null===(o=$.detailDTO)||void 0===o?void 0:o.patientId};null!==q&&void 0!==q&&null!==(s=q.patientPharmacyData)&&void 0!==s&&s.pharmacyId,oe((0,L.Hy)({finalData:d,moveToNext:se}));const c=null===q||void 0===q||null===(l=q.allPatientPharmacyData)||void 0===l?void 0:l.find((e=>e.pharmacyName===Q));c&&(ie("pharmacyLocation",c.pharmacyLocation),ie("country",c.country),ie("pharmacyEmail",c.pharmacyEmail),U(c))})),children:(0,g.jsx)(a.Z,{children:(0,g.jsxs)(o.Z,{lg:12,children:[(0,g.jsxs)("div",{className:"d-flex justify-content-between align-items-baseline",children:[(0,g.jsxs)("span",{className:"w-100",children:[(0,g.jsx)(H.Z.Label,{className:"fw-bold",children:"Pharmacy Name"}),(0,g.jsxs)(H.Z.Group,{children:[null!==q&&void 0!==q&&null!==(e=q.patientPharmacyData)&&void 0!==e&&e.pharmacyName&&!R?(0,g.jsx)("p",{children:null===q||void 0===q||null===(n=q.patientPharmacyData)||void 0===n?void 0:n.pharmacyName}):(0,g.jsx)(V.ReactSearchAutocomplete,{items:null===q||void 0===q||null===(i=q.allPatientPharmacyData)||void 0===i?void 0:i.map((e=>({id:null===e||void 0===e?void 0:e.pharmacyId,name:null===e||void 0===e?void 0:e.pharmacyName,location:null===e||void 0===e?void 0:e.pharmacyLocation,country:null===e||void 0===e?void 0:e.country,display:"".concat(null===e||void 0===e?void 0:e.pharmacyName," - ").concat(null===e||void 0===e?void 0:e.pharmacyLocation)}))),onClear:()=>{ie("pharmacyLocation",""),ie("country",""),U({})},onSearch:(e,n)=>{n?(ie("pharmacyLocation",null===n||void 0===n?void 0:n.location),ie("country",null===n||void 0===n?void 0:n.country),U(n),K(null===n||void 0===n?void 0:n.id)):(ie("pharmacyLocation",""),ie("country",""),U({}))},onSelect:e=>{e&&(X(null===e||void 0===e?void 0:e.name),ie("pharmacyLocation",null===e||void 0===e?void 0:e.location),ie("country",null===e||void 0===e?void 0:e.country),U(e),K(null===e||void 0===e?void 0:e.id))},formatResult:e=>(0,g.jsxs)(g.Fragment,{children:[(0,g.jsx)("span",{style:{display:"block",textAlign:"left"},className:"fw-bold text-wrap",children:null===e||void 0===e?void 0:e.name}),(0,g.jsx)("span",{style:{display:"block",textAlign:"left",fontSize:"15px"},className:"text-wrap",children:null===e||void 0===e?void 0:e.location})]}),autoFocus:!0,placeholder:"Select Pharmacy Name",inputSearchString:null!==(s=null===q||void 0===q||null===(l=q.patientPharmacyData)||void 0===l?void 0:l.pharmacyName)&&void 0!==s?s:"",styling:{height:"46px",border:"1px solid #dee2e6",borderRadius:"0.375rem",boxShadow:"none"},className:"auto__search-field"}),(0,g.jsx)("datalist",{id:"pharmacyNameList",children:null===q||void 0===q||null===(d=q.allPatientPharmacyData)||void 0===d?void 0:d.map((e=>(0,g.jsx)("option",{value:null===e||void 0===e?void 0:e.pharmacyName,children:null===e||void 0===e?void 0:e.pharmacyLocation},null===e||void 0===e?void 0:e.pharmacyId)))})]})]}),(null===q||void 0===q||null===(c=q.patientPharmacyData)||void 0===c?void 0:c.pharmacyId)&&!R&&(0,g.jsxs)("div",{children:[(0,g.jsx)("div",{className:"d-flex justify-content-center align-items-center mb-2",style:{height:"29px",width:"32px",backgroundColor:"#E1EBFF",borderRadius:"5px",cursor:"pointer"},onClick:()=>_(!0),children:(0,g.jsx)(G.HlX,{style:{color:"#2269F2",fontSize:"18px"}})}),(0,g.jsx)("div",{className:"d-flex justify-content-center align-items-center",style:{height:"29px",width:"32px",backgroundColor:"#FFDADD",borderRadius:"5px",cursor:"pointer"},onClick:()=>{M(null===ae||void 0===ae?void 0:ae.patientId),J(!0)},children:(0,g.jsx)(B.w6k,{style:{color:"#E63946",fontSize:"18px"}})})]})]}),(0,g.jsxs)(H.Z.Group,{children:[(0,g.jsx)(H.Z.Label,{className:"fw-bold mt-2",children:"Address"}),null!==q&&void 0!==q&&null!==(u=q.patientPharmacyData)&&void 0!==u&&u.pharmacyLocation&&!R?(0,g.jsx)("p",{children:null===q||void 0===q||null===(m=q.patientPharmacyData)||void 0===m?void 0:m.pharmacyLocation}):(0,g.jsx)(H.Z.Control,{type:"text",placeholder:"Select Address",...ee("pharmacyLocation"),defaultValue:null!==q&&void 0!==q&&null!==(p=q.patientPharmacyData)&&void 0!==p&&p.pharmacyLocation?null===q||void 0===q||null===(v=q.patientPharmacyData)||void 0===v?void 0:v.pharmacyLocation:"",className:"".concat(!(null!==q&&void 0!==q&&q.allPatientPharmacyData)&&"bg-transparent"),readOnly:(null===q||void 0===q||null===(x=q.patientPharmacyData)||void 0===x||!x.pharmacyLocation||!R)&&!(null===q||void 0===q||null===(j=q.patientPharmacyData)||void 0===j||!j.pharmacyLocation),maxLength:250,disabled:!(null!==q&&void 0!==q&&q.allPatientPharmacyData)})]}),(0,g.jsxs)(H.Z.Group,{children:[(0,g.jsx)(H.Z.Label,{className:"fw-bold mt-2",children:"County"}),null!==q&&void 0!==q&&null!==(y=q.patientPharmacyData)&&void 0!==y&&y.country&&!1===R?(0,g.jsx)("p",{children:null===q||void 0===q||null===(f=q.patientPharmacyData)||void 0===f?void 0:f.country}):(0,g.jsx)(H.Z.Control,{type:"text",placeholder:"County",...ee("country"),defaultValue:null!==(N=null===q||void 0===q||null===(b=q.patientPharmacyData)||void 0===b?void 0:b.country)&&void 0!==N?N:"",readOnly:(null===q||void 0===q||null===(D=q.patientPharmacyData)||void 0===D||!D.country||!R)&&!(null===q||void 0===q||null===(I=q.patientPharmacyData)||void 0===I||!I.country),className:"".concat(!(null!==q&&void 0!==q&&q.allPatientPharmacyData)&&"bg-transparent"),maxLength:250,disabled:!(null!==q&&void 0!==q&&q.allPatientPharmacyData)})]}),(0,g.jsxs)(H.Z.Group,{children:[(0,g.jsx)(H.Z.Label,{className:"fw-bold mt-2",children:"Pharmacy Email"}),null!==q&&void 0!==q&&null!==(S=q.patientPharmacyData)&&void 0!==S&&S.pharmacyEmail&&!R?(0,g.jsx)("p",{children:null===q||void 0===q||null===(w=q.patientPharmacyData)||void 0===w?void 0:w.pharmacyEmail}):(0,g.jsx)(H.Z.Control,{type:"email",placeholder:"Pharmacy Email",...ee("pharmacyEmail"),defaultValue:null!==(P=null===q||void 0===q||null===(Z=q.patientPharmacyData)||void 0===Z?void 0:Z.pharmacyEmail)&&void 0!==P?P:"",maxLength:250})]}),(!(null!==q&&void 0!==q&&null!==(C=q.patientPharmacyData)&&void 0!==C&&C.pharmacyId)||R||!(null!==q&&void 0!==q&&null!==(k=q.patientPharmacyData)&&void 0!==k&&k.pharmacyEmail))&&(0,g.jsxs)(h.Z,{className:"px-3 mt-3 primary_bg float-right",size:"sm",type:"submit",children:[null!==q&&void 0!==q&&null!==(E=q.patientPharmacyData)&&void 0!==E&&E.pharmacyId||null===q||void 0===q||null===(A=q.patientPharmacyData)||void 0===A||!A.pharmacyEmail?"Update ":"Add ","Pharmacy"]})]})})}),(0,g.jsx)(z.c,{show:Y,onHide:()=>J(!1),heading:"Delete Pharmacy",title:"this pharmacy",removeFunc:function(){const e={patientId:T};oe((0,L.ai)({finalData:e,onCreateSuccess:le}))}})]})}function W(){var e,n,i,h,u,m,p,v,x,j,y,f,N,b,D;const{patientAppointedDetail:I}=(0,r.v9)((e=>e.appointment)),S=JSON.parse(localStorage.getItem("slotDescription")),w=(0,r.I0)();return(0,t.useEffect)((()=>{const e={patientId:null===S||void 0===S?void 0:S.patientId,appointmentId:null===S||void 0===S?void 0:S.appointmentId};w((0,Z.gS)(e))}),[w,null===S||void 0===S?void 0:S.appointmentId,null===S||void 0===S?void 0:S.patientId]),(0,t.useEffect)((()=>{const e={patientId:null===S||void 0===S?void 0:S.patientId};w((0,L.jX)(e))}),[w,null===S||void 0===S?void 0:S.patientId]),(0,t.useEffect)((()=>{const e={appointmentId:null===S||void 0===S?void 0:S.appointmentId};w((0,A.kU)(e))}),[w,null===S||void 0===S?void 0:S.appointmentId]),(0,t.useEffect)((()=>{w((0,L.VT)({pharmacyName:null,pharmacyLocation:null}))}),[w]),(0,g.jsx)("div",{className:"p-4 consultation-main vh-100",children:(0,g.jsxs)(a.Z,{className:"gy-3 h-100",children:[(0,g.jsx)(o.Z,{xl:3,lg:4,md:4,xs:12,className:"h-100 mb-3 generic-h100",children:(0,g.jsx)(E.Z,{name:"".concat(null===I||void 0===I||null===(e=I.detailDTO)||void 0===e?void 0:e.firstName," ").concat(null===I||void 0===I||null===(n=I.detailDTO)||void 0===n?void 0:n.lastName),genderInfo:"true",gender:null===I||void 0===I||null===(i=I.detailDTO)||void 0===i?void 0:i.gender,dobInfo:"true",dob:null===I||void 0===I||null===(h=I.detailDTO)||void 0===h?void 0:h.dob,currentLocationInfo:"true",currentLocation:null===I||void 0===I||null===(u=I.detailDTO)||void 0===u?void 0:u.currentAddress,patientLocalGPInfo:"true",patientLocalGP:null===I||void 0===I||null===(m=I.detailDTO)||void 0===m?void 0:m.patientLocalGP,emailInfo:"true",email:null===I||void 0===I||null===(p=I.detailDTO)||void 0===p?void 0:p.email,phoneInfo:"true",phone:null===I||void 0===I||null===(v=I.detailDTO)||void 0===v?void 0:v.phoneNumber,image:null===I||void 0===I||null===(x=I.detailDTO)||void 0===x?void 0:x.imageUrl})}),(0,g.jsx)(o.Z,{xl:6,lg:8,md:8,xs:12,className:"bg-white px-0 border__radius-10",style:{height:"50rem"},children:(0,g.jsx)(s.Z,{className:"tele-consultation-tabs",children:(0,g.jsx)(s.Z.Body,{className:"p-0",children:(0,g.jsx)(l.Z,{defaultActiveKey:"videoAppointment",id:"uncontrolled-tab-example",children:(0,g.jsx)(d.Z,{eventKey:"videoAppointment",title:"Appointment",children:(0,g.jsx)(k,{slotDescription:S})})})})})}),(0,g.jsx)(o.Z,{xl:3,lg:6,md:12,xs:12,children:(0,g.jsx)(s.Z,{className:"tele-consultation-accordion h-100",children:(0,g.jsx)(s.Z.Body,{children:(0,g.jsxs)("div",{className:"patient__medical-details",children:[(0,g.jsxs)(c.Z,{defaultActiveKey:"0",children:[(0,g.jsxs)(c.Z.Item,{eventKey:"0",className:"my-3",children:[(0,g.jsx)(c.Z.Header,{children:(0,g.jsx)("h5",{className:"mb-0",children:"Past Medical History"})}),(0,g.jsx)(c.Z.Body,{className:"py-4",children:null!==I&&void 0!==I&&null!==(j=I.patientHistory)&&void 0!==j&&j.pastMedicalHistory?null===I||void 0===I||null===(y=I.patientHistory)||void 0===y?void 0:y.pastMedicalHistory:"N/A"})]}),(0,g.jsxs)(c.Z.Item,{eventKey:"1",className:"my-3",children:[(0,g.jsx)(c.Z.Header,{children:(0,g.jsx)("h5",{className:"mb-0",children:"Current Medications"})}),(0,g.jsx)(c.Z.Body,{className:"py-4",children:null!==I&&void 0!==I&&null!==(f=I.patientHistory)&&void 0!==f&&f.currentMedical?null===I||void 0===I||null===(N=I.patientHistory)||void 0===N?void 0:N.currentMedical:"N/A"})]}),(0,g.jsxs)(c.Z.Item,{eventKey:"2",className:"my-3",children:[(0,g.jsx)(c.Z.Header,{children:(0,g.jsx)("h5",{className:"mb-0",children:"Allergy (to any medication)"})}),(0,g.jsx)(c.Z.Body,{className:"py-4",children:null!==I&&void 0!==I&&null!==(b=I.patientHistory)&&void 0!==b&&b.allergyHistory?null===I||void 0===I||null===(D=I.patientHistory)||void 0===D?void 0:D.allergyHistory:"N/A"})]}),(0,g.jsxs)(c.Z.Item,{eventKey:"3",className:"my-3",children:[(0,g.jsx)(c.Z.Header,{children:(0,g.jsx)("h5",{className:"mb-0",children:"Appointment Reason"})}),(0,g.jsx)(c.Z.Body,{className:"py-4",children:null!==S&&void 0!==S&&S.reasonForAppoinment?null===S||void 0===S?void 0:S.reasonForAppoinment:"N/A"})]})]}),(0,g.jsxs)(s.Z,{className:"border",children:[(0,g.jsx)(s.Z.Header,{children:"Pharmacy"}),(0,g.jsx)(s.Z.Body,{children:(0,g.jsx)(K,{})})]})]})})})}),(0,g.jsx)(o.Z,{xl:3,lg:6,md:12,xs:12,children:(0,g.jsx)(s.Z,{children:(0,g.jsx)(s.Z.Body,{children:(0,g.jsx)(O,{})})})}),(0,g.jsx)(o.Z,{xl:6,lg:12,md:12,xs:12,children:(0,g.jsx)(T.default,{})})]})})}}}]);
//# sourceMappingURL=9949.47b692dd.chunk.js.map