---
title: "OffensiveLLVM Part 1"
date: 2025-08-13T21:40:22+02:00
---

```
Little disclaimer: I'm a novice with LLVM—my only experience is about two days of writing passes and trying to learn how everything works. If you spot any misinterpretations or errors, let me know! ;)
```


You’ve probably already heard of **OLLVM**, which is basically a compiler that obfuscates your code. But what is it exactly, and if it exists, why can’t we do the same?

OLLVM is based on **LLVM** (Low Level Virtual Machine), which acts as a backend for various compilers. LLVM lifts code into an intermediate representation called **LLVM IR** . The code is then compiled into machine code using a toolchain. The key feature here is that you can apply transformations to the code between the IR stage and the final machine code generation. These transformations are called **passes**.

These passes allow you to modify the code at the granularity of individual instructions. For example, you can add functions, split basic blocks, modify constants, etc.

I’ve been interested in obfuscation since seeing [es3n1n’s Bin2Bin obfuscator](https://blog.es3n1n.eu/posts/obfuscator-pt-1/). A full bin2bin obfuscator seemed daunting, so I opted for a simpler **source-to-bin** approach. After a year of procrastination, I spent a weekend writing LLVM passes for:

The goal of these passes is to:

- Cipher constants, strings, and variables, and only decipher them at runtime.
- Apply simple MBA (Mixed Boolean-Arithmetic) transformations.
- Apply CFF (Control Flow Flattening).
- And finally some 'offensive things', like replacing a simple GetProcAddress with a custom one using hashes, for example.

One nice thing is that since these transformations happen between IR → MC (machine code), and many languages use LLVM (Rust, C++, C, Nim, and even Go with some OSS compilers), it’s quite versatile.

---

**Compiling LLVM**  
I’m doing this on Windows, so some steps might differ on Linux.

```bash
git clone https://github.com/llvm/llvm-project.git
cmake -G "Ninja" -DLLVM_ROOT=llvm-project\build ..
ninja
```


### **Writing a simple pass**

We’ve seen that passes let you change the IR at instruction-level granularity. But how do you write them? LLVM supports multiple kinds of passes **FunctionPass**, **ModulePass**, **LoopPass**, **MachineCodePass** etc. 
But also different ways of building them, in-tree and out-of-tree. In this example, I’ll do **out-of-tree** because it’s easier and more portable.
We’ll only write a FunctionPass for now

A simple pass can be decomposed into two parts:

- **Registration**: How we link our pass into LLVM.

- **Execution**: The actual transformation logic.

**Registration example:**

```cpp
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "ObfsPass", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "myobf") {
            FPM.addPass(ObfsPass());
            return true;
          }
          return false;
        });
    }
  };
}
```

In this example, we use the new pass plugin manager.
- `ObfsPass` is the name of our class containing the transformation logic.
- `"myobf"` is the pass name used in the command line.
For example, to run this pass:

```shell
opt -load-pass-plugin=./bin/LLVMMyObfsPass.dll -passes=myobf   -o test_obf.ll test.ll
```

if we modify it a little to get output

```cpp
if (Name == "myobf") {
	llvm::outs() << "Hi" << std::endl;
            FPM.addPass(ObfsPass());
            return true;
          }
     
```

```bash
bin\opt -load-pass-plugin=./bin/LLVMMyObfsPass.dll -passes=myobf   -o .\test_obf.ll test.ll
Hi
Hi

```

---
### **Compiling the Pass**


Inside `llvm/lib/Transforms/`, create a directory for your pass 

inside the **CMakeLists.txt** of Transforms add the name of directory you created
```cmake
add_subdirectory(MyObfsPass)
```
Inside your directory create your own **CMakeLists.txt** 

```cmake
#SHARED is used to create a dll
add_llvm_library(LLVMMyObfsPass SHARED
  <file>.cpp
  PLUGIN_TOOL
  opt
  LINK_COMPONENTS
  Core IRReader Support AsmParser BitReader Linker
)
#Define the name of our output
set_target_properties(LLVMMyObfsPass PROPERTIES
  PREFIX ""
  OUTPUT_NAME "LLVMMyObfsPass"
  SUFFIX ".dll"
  WINDOWS_EXPORT_ALL_SYMBOLS ON
)
```

and after in LLVM_source/build we can use 
``ninja LLVMMyObfsPass``
To know the name you can use 
```bash
ninja -t targets | findstr.exe "Obf"
lib/LLVMMyObfsPass.lib: 
[...]
LLVMMyObfsPass: phony
LLVMMyObfsPass.dll: phony
[...]
```

Now everything should be set up, we will begin with this very basic example.

In this example, we will only check for the main function. For each basic block of the function and each instruction, we get the operands, and if it's a ConstantInt, let's modify it to **42**.

```cpp

#include "llvm/Transforms/MyObfsPass/Obf.h"

using namespace llvm;


PreservedAnalyses ObfsPass::run(Function &F, FunctionAnalysisManager &AM) {
//print the function name
  outs() << "Processing function: " << F.getName() << "\n";
  if (F.getName() != "main") {
    outs() << "Skipping function: " << F.getName() << "\n";
    return PreservedAnalyses::all();
  }
  IRBuilder<> Builder(F.getContext());
  bool Changed = false;
  //for the current function, find parse every BasicBlocks
  for (BasicBlock &BB : F) {
  //For each BasicBlock, parse every instruction
    for (Instruction &I : BB) {
    //Get operands for all instructions
      for (unsigned i = 0; i < I.getNumOperands(); i++) {
        Value *Op = I.getOperand(i);
        //if it's a ConstantInt we change it to 42
        if (ConstantInt *CI = dyn_cast<ConstantInt>(Op)) {
          errs() << "Found constant: " << CI->getValue() << " in instruction: " << I << "\n";
          I.setOperand(i, ConstantInt::get(CI->getType(), 42));
          Changed = true;
        }
      }
    }
  }
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();

}
[PassPluginLibraryInfo.... ]
```


Let's test it!


As an example, let's write this simple C code

```c
#add.c
#include <stdio.h>
int main(){
        int a = 10;
        int b = 12;
        printf("a + b = %d",a+b);
        return 1;
}

```
```bash
clang test.c
```

![](main_simple.png)

Now we can apply the pass we wrote and see if it's working

```bash
clang -emit-llvm -S -O0 -Xclang -disable-O0-optnone -g test.c -o test.ll
```
```bash
opt -load-pass-plugin=./bin/LLVMMyObfsPass.dll -passes=myobf   -o test_obf.ll test.ll

```
---
```bash

Processing function: main
Found constant: 1 in instruction:   %1 = alloca i32, align 4
Found constant: 1 in instruction:   %2 = alloca i32, align 4
Found constant: 1 in instruction:   %3 = alloca i32, align 4
Found constant: 0 in instruction:   store i32 0, ptr %1, align 4
Found constant: 10 in instruction:   store i32 10, ptr %2, align 4, !dbg !33
Found constant: 12 in instruction:   store i32 12, ptr %3, align 4, !dbg !35
Found constant: 1 in instruction:   ret i32 1, !dbg !37
Processing function: _vsprintf_l
```
```bash
clang test_obf.ll -o a.exe
```

![](42_replace_int.png)
As you can see, the constants have been modified

### **The Encryption/Decryption Process in Depth**
So let's explain the real passes. First, the objective is to find every string in our code, encrypt it at compile time, and use a simple stub to decrypt and re-encrypt the strings at each use.

First, we will only do this for C, because strings in C are very simple: bytes (char) with a string terminator ('\0').

We can find every string using this:

```cpp
std::vector<StringUsage> FindAllStringUsages(Function &F) {
    std::vector<StringUsage> Usages;
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            for (unsigned i = 0; i < I.getNumOperands(); ++i) {
                Value *Op = I.getOperand(i);
                // Check if operand is a GlobalVariable
                auto *GV = dyn_cast<GlobalVariable>(Op);
                if (!GV)
                    continue;  // Skip if not a GlobalVariable
                // Check if GV is constant and has an initializer
                if (!GV->isConstant() || !GV->hasInitializer())
                    continue;
                // Check if initializer is a ConstantDataArray
                auto *CA = dyn_cast<ConstantDataArray>(GV->getInitializer());
                if (!CA)
                    continue;
                // Check if it's a string
                if (!CA->isString())
                    continue;
                // All conditions met - record the string usage
                Usages.push_back({&I, GV, i});
[...]
```


This code is awful, but it works. We take every instruction of all basic blocks, get the operand, and if we find a ConstantDataArray and it's a string, we can get all the info in our struct.


We can Write the code for the stub :

```cpp
// void deobfuscate(i32 key, i8* str)
    std::vector<Type*> ArgTypes = {
        Type::getInt32Ty(Ctx),
        Type::getInt8Ty(Ctx)->getPointerTo()
    };
    FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), ArgTypes, false);
    Function *DeobfFunc = Function::Create(FT, Function::ExternalLinkage, "deobfuscate", &M);
```


It's how we can define our function, after this we can parse args, and create our BB using

```cpp
BasicBlock *LoopCond = BasicBlock::Create(Ctx, "loop.cond", DeobfFunc);
BasicBlock *LoopBody = BasicBlock::Create(Ctx, "loop.body", DeobfFunc);
BasicBlock *LoopEnd  = BasicBlock::Create(Ctx, "loop.end", DeobfFunc);
```

so we have our BB, this is a simple loop.

And for the instruction, for example, this is the "body" the part of the code that will use quantum-proof encryption, also known as XOR

```cpp
//Add at the end of the basic block
B.SetInsertPoint(LoopBody);
Value *Key8 = B.CreateTrunc(KeyArg, Type::getInt8Ty(Ctx));
Value *Xord = B.CreateXor(Cur, Key8);
B.CreateStore(Xord, PtrPhi); //store into *ptr
Value *Next = B.CreateGEP(Type::getInt8Ty(Ctx), PtrPhi, B.getInt32(1));
//Phi instruction merges values from different control flow paths.
PtrPhi->addIncoming(Next, LoopBody);
B.CreateBr(LoopCond);
```



We can finaly create our encrypted strings

```cpp
ConstantDataArray *CA = cast<ConstantDataArray>(GV->getInitializer());
StringRef Str = CA->getAsString();
std::string XoredStr;
for (char C : Str) {
	if (C == '\0') {
		XoredStr += '\0';
		continue;
		}
	XoredStr += C ^ (char)(Key & 0xFF);
```
We initialize a new String, take the value that we find earlier xor it 

```cpp
//Init new ConstDataArray, this is our new string encrypted
Constant *NewInit = ConstantDataArray::getString(Ctx, XoredStr, false);
            GV->setConstant(false);
            GV->setInitializer(NewInit);
```

and finaly add call to our stub

```cpp
RBuilder<> Builder(UserInst);
        Value *KeyVal = ConstantInt::get(Type::getInt32Ty(Ctx), Key);
        Value *StrPtr = Builder.CreatePointerCast(GV, Type::getInt8Ty(Ctx)->getPointerTo(), "str_ptr_cast");
        //We call our function 2 time before and after to re-encrypt the string
        Builder.CreateCall(DeobfFunc, {KeyVal, StrPtr});
        if (UserInst->getNextNode()) {
            Builder.SetInsertPoint(UserInst->getNextNode());
        } else {
            Builder.SetInsertPoint(UserInst->getParent());
        }
        Builder.CreateCall(DeobfFunc, {KeyVal, StrPtr});
```

So we take the instruction where the strings is used and just before add our decryption and we encrypt it back after use.


### **Modifing function** 


This time we want to replace a function by another. Why? Because it's fun, but also we could change a call to a function like GetProcAddress to a custom one using hashes. No need to think of evasion if your compiler is kind.


Let's take our earlier example : 

```c
#add.c
#include <stdio.h>
int add(int a, int b){
        return (a+b);
}
int main(){
        int a = 10;
        int b = 12;
        printf("a + b = %d",add(a,b));
        return 1;
}
```

```bash
#We transforme it to LLIR
clang -emit-llvm -S -O0 -Xclang -disable-O0-optnone -g add.c -o add.ll
```

let's create our other func in an other file

```c
#sub.c
int sub(int a, int b){
        return (a - b);
}
```

```bash
llvm-project\build>clang -emit-llvm -c sub.c -o sub.bc

llvm-project\build>xxd -i sub.bc
unsigned char sub_bc[] = {
  0x42, 0x43, 0xc0, 0xde, 0x35, 0x14, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
  0x62, 0x0c, 0x30, 0x24, 0x4a, 0x59, 0xbe, 0x66, 0xdd, 0xfb, 0xb5, 0x9f,
  [...]
```

We can now import this as a header file.


inside our pass, it's possible to create a function like this one, take current module, bytecode array and size, parse it using parseBitcodeFile and link to the current module

```cpp
bool ObfsPass::InMemoryLLVM(llvm::Module &M, const unsigned char bc[], unsigned int bc_len) {
    LLVMContext &Context = M.getContext();
    auto MemBuffer = llvm::MemoryBuffer::getMemBuffer(
        llvm::StringRef(reinterpret_cast<const char*>(bc), bc_len),
        "bytecode",
        false
    );
    Module Module = parseBitcodeFile(MemBuffer->getMemBufferRef(), Context);
    if (!Module) {
        return false;
    }
    std::unique_ptr<Module> ExternalMod = std::move(*Module);
    ExternalMod->setModuleIdentifier("external_module");
    Linker L(M);
    if (L.linkInModule(std::move(ExternalMod))) {
        return false;
    }
    return true;
}
```

And finally we can take the to functions, take every call of add, and replace with a call of sub

```cpp
    if (!InMemoryLLVM(M, sub_bc, sub_bc_len)) {
        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
    // Now let's find it (because we linked it into current module)
    Function *SubFunction = M.getFunction("sub");
    Function *AddFunction = M.getFunction("add");

    if(!SubFunction && AddFunction ){
        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    //replace all calls to "sub" with a call to "add"

	//get all call of AddFunction, and for each one change to SubFunction
	for (auto &U : AddFunction->uses()) {

        if (CallInst *CI = dyn_cast<CallInst>(U.getUser())) {

            CI->setCalledFunction(SubFunction);

        }

    }
```

and if we compile it.

(don't look at the debugbreak it's for later)

![](/CallAddBecomSub_1.png))
![](/CallAddBecomSub_2.png)
As you can see, we replace the called function by an other.

Next time let's see how create MachineLevelPasses to permit changing things during machine code generation.
