import {compileSchema} from './configuration-schema.mjs';
import {decodeWire,profile} from './configuration-wire.mjs';
const maxBytes=1048576,budget=profile({max_message_bytes:maxBytes,max_depth:32,max_value_nodes:65536,max_object_members:4096,
  max_key_utf8_bytes:1024,max_string_utf8_bytes:maxBytes,parse_deadline_ms:2000});
let bytes=0;const chunks=[];
const timer=setTimeout(()=>process.exit(1),3000);process.stdin.on('error',()=>process.exit(1));
process.stdin.on('data',chunk=>{bytes+=chunk.length;if(bytes>2800000)process.exit(1);chunks.push(chunk);});
process.stdin.on('end',async()=>{
  try{
    const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if(!input||Object.keys(input).sort().join(',')!=='configuration,mode,schema'||!['configuration','schemas'].includes(input.mode))throw new Error();
    const decode=text=>{if(typeof text!=='string')throw new Error();const buffer=Buffer.from(text,'base64');if(buffer.length>maxBytes||buffer.toString('base64')!==text)throw new Error();return buffer;};
    const schemaBytes=decode(input.schema),configuration=decode(input.configuration),yieldNow=()=>new Promise(resolve=>setImmediate(resolve));
    const parsed=await decodeWire(schemaBytes,compileSchema(true),{profile:budget,yieldNow});
    if(input.mode==='schemas'){
      if(configuration.length!==0||!Array.isArray(parsed.value)||parsed.value.length>256)throw new Error();
      for(const document of parsed.value)compileSchema(document);
      process.stdout.write(JSON.stringify({ok:true,value:null})+'\n');return;
    }
    const selected=compileSchema(parsed.value);
    const result=await decodeWire(configuration,selected,{profile:budget,yieldNow});
    process.stdout.write(JSON.stringify({ok:true,value:result.value})+'\n');
  }catch(error){
    const code=['schema_rejected','raw_integer','integer_range','external_reference','schema_compile','schema_budget','reserved_keyword','dialect',
      'duplicate_key','unicode_scalar','utf8_invalid','json_grammar'].includes(error?.reason)?error.reason:'configuration_invalid';
    process.stdout.write(JSON.stringify({ok:false,code})+'\n');
  }finally{clearTimeout(timer);}
});
