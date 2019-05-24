/*
 * Copyright (c) 2016 Sasha Goldshtein
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <fstream>
#include <regex>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/MultiplexConsumer.h>
#include <clang/Rewrite/Core/Rewriter.h>

#include "frontend_action_common.h"
#include "tp_frontend_action.h"

namespace ebpf {

using std::map;
using std::set;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;
using std::regex;
using std::smatch;
using std::regex_search;
using std::ifstream;
using namespace clang;

TracepointTypeVisitor::TracepointTypeVisitor(ASTContext &C, Rewriter &rewriter)
    : C(C), diag_(C.getDiagnostics()), rewriter_(rewriter), out_(llvm::errs()) {
}

enum class field_kind_t {
    common,
    data_loc,
    regular,
    invalid
};

static inline field_kind_t _get_field_kind(string const& line,
                                           string& field_type,
                                           string& field_name) {
  auto field_pos = line.find("field:");
  if (field_pos == string::npos)
    return field_kind_t::invalid;

  auto field_semi_pos = line.find(';', field_pos);
  if (field_semi_pos == string::npos)
    return field_kind_t::invalid;

  auto offset_pos = line.find("offset:", field_semi_pos);
  if (offset_pos == string::npos)
    return field_kind_t::invalid;

  auto semi_pos = line.find(';', offset_pos);
  if (semi_pos == string::npos)
    return field_kind_t::invalid;

  auto size_pos = line.find("size:", semi_pos);
  if (size_pos == string::npos)
    return field_kind_t::invalid;

  semi_pos = line.find(';', size_pos);
  if (semi_pos == string::npos)
    return field_kind_t::invalid;

  auto size_str = line.substr(size_pos + 5,
                              semi_pos - size_pos - 5);
  int size = std::stoi(size_str, nullptr);

  auto field = line.substr(field_pos + 6/*"field:"*/,
                           field_semi_pos - field_pos - 6);
  auto pos = field.find_last_of("\t ");
  if (pos == string::npos)
    return field_kind_t::invalid;

  field_type = field.substr(0, pos);
  field_name = field.substr(pos + 1);
  if (field_type.find("__data_loc") != string::npos)
    return field_kind_t::data_loc;
  if (field_name.find("common_") == 0)
    return field_kind_t::common;
  // do not change type definition for array
  if (field_name.find("[") != string::npos)
    return field_kind_t::regular;

  // adjust the field_type based on the size of field
  // otherwise, incorrect value may be retrieved for big endian
  // and the field may have incorrect structure offset.
  if (size == 2) {
    if (field_type == "char" || field_type == "int8_t")
      field_type = "s16";
    if (field_type == "unsigned char" || field_type == "uint8_t")
      field_type = "u16";
  } else if (size == 4) {
    if (field_type == "char" || field_type == "short" ||
        field_type == "int8_t" || field_type == "int16_t")
      field_type = "s32";
    if (field_type == "unsigned char" || field_type == "unsigned short" ||
        field_type == "uint8_t" || field_type == "uint16_t")
      field_type = "u32";
  } else if (size == 8) {
    if (field_type == "char" || field_type == "short" || field_type == "int" ||
        field_type == "int8_t" || field_type == "int16_t" ||
        field_type == "int32_t" || field_type == "pid_t")
      field_type = "s64";
    if (field_type == "unsigned char" || field_type == "unsigned short" ||
        field_type == "unsigned int" || field_type == "uint8_t" ||
        field_type == "uint16_t" || field_type == "uint32_t" ||
        field_type == "unsigned" || field_type == "u32" ||
        field_type == "uid_t" || field_type == "gid_t")
      field_type = "u64";
  }

  return field_kind_t::regular;
}

string TracepointTypeVisitor::GenerateTracepointStruct(
    SourceLocation loc, string const& category, string const& event) {
  string format_file = "/sys/kernel/debug/tracing/events/" +
    category + "/" + event + "/format";
  ifstream input(format_file.c_str());
  if (!input)
    return "";

  string tp_struct = "struct tracepoint__" + category + "__" + event + " {\n";
  tp_struct += "\tu64 __do_not_use__;\n";
  for (string line; getline(input, line); ) {
    string field_type, field_name;
    switch (_get_field_kind(line, field_type, field_name)) {
    case field_kind_t::invalid:
    case field_kind_t::common:
        continue;
    case field_kind_t::data_loc:
        tp_struct += "\tint data_loc_" + field_name + ";\n";
        break;
    case field_kind_t::regular:
        tp_struct += "\t" + field_type + " " + field_name + ";\n";
        break;
    }
  }

  tp_struct += "};\n";
  return tp_struct;
}

static inline bool _is_tracepoint_struct_type(string const& type_name,
                                              string& tp_category,
                                              string& tp_event) {
  // We are looking to roughly match the regex:
  //    (?:struct|class)\s+tracepoint__(\S+)__(\S+)
  // Not using std::regex because older versions of GCC don't support it yet.
  // E.g., the libstdc++ that ships with Ubuntu 14.04.

  auto first_space_pos = type_name.find_first_of("\t ");
  if (first_space_pos == string::npos)
    return false;
  auto first_tok = type_name.substr(0, first_space_pos);
  if (first_tok != "struct" && first_tok != "class")
    return false;

  auto non_space_pos = type_name.find_first_not_of("\t ", first_space_pos);
  auto second_space_pos = type_name.find_first_of("\t ", non_space_pos);
  auto second_tok = type_name.substr(non_space_pos,
                                     second_space_pos - non_space_pos);
  if (second_tok.find("tracepoint__") != 0)
    return false;

  auto tp_event_pos = second_tok.rfind("__");
  if (tp_event_pos == string::npos)
    return false;
  tp_event = second_tok.substr(tp_event_pos + 2);

  auto tp_category_pos = second_tok.find("__");
  if (tp_category_pos == tp_event_pos)
    return false;
  tp_category = second_tok.substr(tp_category_pos + 2,
                                  tp_event_pos - tp_category_pos - 2);
  return true;
}

SourceRange
TracepointTypeVisitor::expansionRange(SourceRange range) {
#if LLVM_MAJOR_VERSION >= 7
  return rewriter_.getSourceMgr().getExpansionRange(range).getAsRange();
#else
  return rewriter_.getSourceMgr().getExpansionRange(range);
#endif
}

SourceLocation
TracepointTypeVisitor::expansionLoc(SourceLocation loc) {
  return rewriter_.getSourceMgr().getExpansionLoc(loc);
}

bool TracepointTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  if (D->hasBody()) {
    current_fn_ = D->getName();

    // Get the actual function declaration point (the macro instantiation
    // point if using the TRACEPOINT_PROBE macro instead of the macro
    // declaration point in bpf_helpers.h).
    SourceLocation begin_loc = GET_BEGINLOC(D);
    begin_loc = rewriter_.getSourceMgr().getFileLoc(begin_loc);
    SourceLocation end_loc = GET_ENDLOC(D);
    end_loc = rewriter_.getSourceMgr().getFileLoc(end_loc);

    string func_src = rewriter_.getRewrittenText(SourceRange(begin_loc, end_loc));

    if (D->isExternallyVisible()) {
      // Add __fake__ marker in name for the duplicate function.
      if (func_src.find("TRACEPOINT_PROBE(") == 0)
        func_src.replace(0, 17, "TRACEPOINT_PROBE(fake__");
      else if (func_src.find("RAW_TRACEPOINT_PROBE(") == 0)
        func_src.replace(0, 21, "RAW_TRACEPOINT_PROBE(fake__");
      else if (size_t pos = func_src.find('('))
        if (pos != string::npos)
          func_src.replace(pos, 1, "__fake__(");

      // If this function has a tracepoint structure as an argument,
      // add that structure declaration based on the structure name.
      for (auto it = D->param_begin(); it != D->param_end(); ++it) {
        auto arg = *it;
        auto type = arg->getType();
        if (type->isPointerType() &&
            type->getPointeeType()->isStructureOrClassType()) {
          auto type_name = type->getPointeeType().getAsString();
          string tp_cat, tp_evt;
          if (_is_tracepoint_struct_type(type_name, tp_cat, tp_evt)) {
            string tp_struct = GenerateTracepointStruct(GET_BEGINLOC(D), tp_cat, tp_evt);
            string fake_struct = tp_struct;
            // Since function name was changed, the tracepoint structure
            // needs to be as well.
            fake_struct.replace(0, 19, "struct tracepoint__fake__");
            tp_struct += "\n" + fake_struct;
            rewriter_.InsertText(begin_loc, tp_struct);
          }
        }
      }
    } else {
      // Add __fake__ marker in name for the duplicate function.
      size_t pos = func_src.find('(');
      if (pos != string::npos)
        func_src.replace(pos, 1, "__fake__(");
    }

    // Replace all call within the doubled function.
    for (string fn : functions_) {
      size_t last_pos = 0, pos = 0;
      while (last_pos < func_src.length() && pos != string::npos) {
        pos = func_src.find(fn + "(", last_pos);
        if (pos != string::npos) {
          size_t fn_end = pos + fn.length();
          if (func_src.find("__fake__", fn_end) != fn_end)
            func_src.replace(fn_end, 0, "__fake__");
          last_pos = fn_end;
        }
      }
    }

    // Let's double that function and move it to a different section.
    func_src = "\n\n" + func_src;
    rewriter_.InsertTextAfterToken(expansionLoc(end_loc), func_src);
  }
  return true;
}

TracepointTypeConsumer::TracepointTypeConsumer(ASTContext &C, Rewriter &rewriter)
    : visitor_(C, rewriter), rewriter_(rewriter) {
}

bool TracepointTypeConsumer::HandleTopLevelDecl(DeclGroupRef Group) {
  FileID main_file_id = rewriter_.getSourceMgr().getMainFileID();
  // Iterate on all function to identify functions that
  // will need to be duplicated.
  for (auto D : Group)
    if (FunctionDecl *F = dyn_cast<FunctionDecl>(D)) {
        SourceLocation loc = rewriter_.getSourceMgr().getFileLoc(GET_BEGINLOC(F));
        FileID file_id = rewriter_.getSourceMgr().getFileID(loc);
        if (F->hasBody() && file_id == main_file_id)
          visitor_.set_fn(F->getName());
    }
  for (auto D : Group)
    visitor_.TraverseDecl(D);
  return true;
}

TracepointFrontendAction::TracepointFrontendAction(llvm::raw_ostream &os)
    : os_(os), rewriter_(new Rewriter) {
}

void TracepointFrontendAction::EndSourceFileAction() {
  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(os_);
  os_.flush();
}

unique_ptr<ASTConsumer> TracepointFrontendAction::CreateASTConsumer(
        CompilerInstance &Compiler, llvm::StringRef InFile) {
  rewriter_->setSourceMgr(Compiler.getSourceManager(), Compiler.getLangOpts());
  return unique_ptr<ASTConsumer>(new TracepointTypeConsumer(
              Compiler.getASTContext(), *rewriter_));
}

}
