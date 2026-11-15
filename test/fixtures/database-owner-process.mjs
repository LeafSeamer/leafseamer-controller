import {openStorage,migrateStorage} from '../../dist/storage.mjs';
const [mode,directory]=process.argv.slice(2);
try{
 if(mode==='migrate')await migrateStorage(directory,67);
 else{const store=openStorage(directory);if(mode==='hold'){process.stdout.write('ready\n');setInterval(()=>{},1000);process.on('SIGTERM',()=>{store.close();process.exit(0);});}else store.close();}
 if(mode!=='hold')process.stdout.write('opened\n');
}catch(error){process.stdout.write(String(error.code??error.message)+'\n');process.exitCode=2;}
