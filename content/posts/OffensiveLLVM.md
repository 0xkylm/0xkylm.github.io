---
title: "OffensiveLLVM Part 1"
date: 2025-08-13T21:40:22+02:00
---

## **Introduction to LLVM**

```
Disclaimer: I'm a novice with LLVM—my only experience is about two days of writing passes and trying to learn how everything works. If you spot any misinterpretations or errors, let me know! ;)
```

Have you already heard of **OLLVM**, a compiler that outputs obfuscated binaries? Probably. But what is it exactly? Can we achieve something similar ?

OLLVM is based on **LLVM** (Low Level Virtual Machine), which serves as a backend for various compilers. LLVM lifts code into an Intermediate Representation called **LLVM IR** (LLIR). The code is then compiled into machine code using a toolchain. The key feature here is that you can apply transformations to the code between the IR stage and the final machine code generation. These transformations are called **passes**.

Passes allow you to modify the code at the granularity of individual instructions. For example, you can add functions, split basic blocks, modify constants, etc.

I’ve been interested in obfuscation since I’ve came across [es3n1n’s Bin2Bin obfuscator](https://blog.es3n1n.eu/posts/obfuscator-pt-1/). A full binary-to-binary obfuscator seemed daunting, so I opted for a simpler **source-to-bin** approach. After a year of procrastination, I spent a full weekend writing LLVM passes.

The goal of these passes is to:

- Encrypt constants, strings, and variables, and only decrypt them at runtime.
- Apply simple MBA (Mixed Boolean-Arithmetic) transformations.
- Apply CFF (Control Flow Flattening).
- And finally some "offensive things", like replacing GetProcAddress calls by a custom manual resolution function that uses API hashing for example.

A nice thing is that since these transformations happen between IR → MC (machine code), and many languages use LLVM (C, C++, Rust, Nim, and even Go with some OSS compilers) making it quite versatile.

---

### **Compiling LLVM**  
I’m doing this on Windows, so some steps might differ on Linux.

```bash
git clone https://github.com/llvm/llvm-project.git
cmake -G "Ninja" -DLLVM_ROOT=llvm-project\build ..
ninja
```

**Registration example:**
We mentioned earlier that passes let you change IR with instruction-level granularity. But how do you write them? LLVM supports multiple kinds of passes **FunctionPass**, **ModulePass**, **LoopPass**, **MachineCodePass** etc. 
But also different ways of building them, in-tree and out-of-tree. In this example, I’ll focus on **out-of-tree** because it’s easier and more portable and only on FunctionPass for now.

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

To run this pass:

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

In the ``llvm/lib/Transformation/`` directory, create a folder for your pass. Then, in the ``CmakeList.txt`` of Transforms add the name of folder you created.

```cmake
add_subdirectory(MyObfsPass)
```

In this new directory, create your own ``CmakeList.txt``. 

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

To find the name of the build target, you can use the following command:

```bash
ninja -t targets | findstr.exe "Obf"
lib/LLVMMyObfsPass.lib: 
[...]
LLVMMyObfsPass: phony
LLVMMyObfsPass.dll: phony
[...]
```

Finally, we can build the pass by running the following command in LLVM_source/build:

```
ninja LLVMMyObfsPass
```


Now everything should be setup ! Let’s begin with a very basic example.

We will go through the main function, for each basic block of the function and each instruction we get the operand and if it's a *ConstantInt*, let's modify to **42**.

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

We will take this simple C code as an example:

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

![](/main_simple.png)

Now we can apply the pass we wrote and see if it works:

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

![](/42_replace_int.png)
As you can see, the constants have been modified.

### **The Encryption/Decryption Process in Depth**

Now let's see some real passes. The first one is to find every string in our code, encrypt it at compile time and add a simple stub that will decrypt and encrypt back the string during runtime, when the string is "used".

We will only do this for C because, C-strings are very simple: bytes (char) with a null-byte terminator ('\0').

We can find every string using the following code:

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

The code is awful but it works. We take every Instruction of every BasicBlock, get the Operand, and if we find a *ConstantDataArray* that is a string (as described before), we can get all information in our structure.

Then, we can write the code for the stub.

```cpp
// void deobfuscate(i32 key, i8* str)
    std::vector<Type*> ArgTypes = {
        Type::getInt32Ty(Ctx),
        Type::getInt8Ty(Ctx)->getPointerTo()
    };
    FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), ArgTypes, false);
    Function *DeobfFunc = Function::Create(FT, Function::ExternalLinkage, "deobfuscate", &M);
```

This is how we can define our function. After that, we can parse arguments and create our *BasicBlock* using the following code:

```cpp
BasicBlock *LoopCond = BasicBlock::Create(Ctx, "loop.cond", DeobfFunc);
BasicBlock *LoopBody = BasicBlock::Create(Ctx, "loop.body", DeobfFunc);
BasicBlock *LoopEnd  = BasicBlock::Create(Ctx, "loop.end", DeobfFunc);
```

This code creates three LLVM basic blocks inside DeobfFunc that represent a loop’s control flow:
loop.cond checks the condition, loop.body contains the loop’s instructions, and loop.end runs after the loop finishes.

For example, this is the "body" the part of the code that will use quantum-proof encryption, also known as XOR.

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

We can finaly create our encrypted string:

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
We initialize a new String, take the value that we find earlier XOR it.

```cpp
//Init new ConstDataArray, this is our new string encrypted
Constant *NewInit = ConstantDataArray::getString(Ctx, XoredStr, false);
            GV->setConstant(false);
            GV->setInitializer(NewInit);
```

Finally, we add a call to our stub:

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

Just before the string is used, we add our decryption routine, and revert back to its encrypted form when done.

### **Modifing function** 

Now, we want to replace a function by another one. But why? Because it's fun. Also we could change a call to a function like a GetProcAdress with a custom one that uses API hashing. You don’t need to think about evasion if you compiler is kind enough to do it for you.

Let's take our previous example : 

```c
// add.c
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

Let's create the replacement function in an other file:

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

In our pass, it's possible to create a function like this one, take current module, bytecode array and size, parse it using parseBitcodeFile and link it to the current module.

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

Finally we can replace every call to add with a call to sub.

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

![](/CallAddBecomSub_1.png)
![](/CallAddBecomSub_2.png)

As you can see, we replaced the called function by another.

Next time we will see how to create MachineLevelPasses that allow to change "things" during machine code generation.

Thanks [Atsika](https://x.com/_atsika) for the review
