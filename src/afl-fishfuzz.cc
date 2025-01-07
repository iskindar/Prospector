#include "afl-fuzz.h"

#include <jsoncpp/json/json.h>
#include <fstream>
#include <math.h>
#include <algorithm>
#include <sys/time.h>
#include <map>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
#include <chrono>

#ifdef __cplusplus
extern "C" {
#endif

std::map<u32, std::map<u32, double>> func_dist_map;
std::map<u32, std::vector<u32>>      func_reachable_map;
std::map<u32, std::vector<u32>>      funcid2targetid_map;
std::map<u32, u32>                   targetid2funcid_map;
u8                                   unvisited_func_map[FUNC_SIZE];

std::vector<u32> seed_length;
/* initialize loading static maps */

void initialized_bug_map() {
  std::string                temporary_dir = std::getenv("TMP_DIR");
  std::map<std::string, u32> func2id;
  std::ifstream              fi(temporary_dir + "/funcid.csv");
  if (fi.is_open()) {
    std::string line;
    while (getline(fi, line)) {
      std::size_t dis_pos = line.find(",");
      std::string fname = line.substr(dis_pos + 1, line.length() - dis_pos);
      std::string idx_str = line.substr(0, dis_pos);
      func2id.emplace(fname, atoi(idx_str.c_str()));
      // std::cout << fname << " : " << idx_str << "\n";
    }
  }

  /* initialized vuln functions */
  std::ifstream bfunc(temporary_dir + "/vulnfunc.csv", std::ifstream::binary);
  if (bfunc.is_open()) {
    std::string line;
    while (getline(bfunc, line)) {
      auto biter = func2id.find(line);
      if (biter != func2id.end()) {
        if (biter->second < FUNC_SIZE) unvisited_func_map[biter->second] = 1;
      }
      // else PFATAL("Failed found func %s.", line.c_str());
    }
  }
}
// load priority-based map
void initialized_dist_map_p() {
  Json::Value   shortest_dist_map;
  Json::Value   shortest_call_map;
  Json::Reader  dist_reader;
  Json::Reader  call_reader;
  std::string   temporary_dir = std::getenv("TMP_DIR"), errs;
  std::ifstream dist_map(temporary_dir + "/runtimes/calldst_p.json",
                         std::ifstream::binary);
  std::ifstream call_map(temporary_dir + "/runtimes/callmap_p.json",
                         std::ifstream::binary);

  if (!dist_reader.parse(dist_map, shortest_dist_map, false))
    PFATAL("Failed loading dist map !");
  if (!call_reader.parse(call_map, shortest_call_map, false))
    PFATAL("Failed loading call map !");

  for (auto dst_s : shortest_dist_map.getMemberNames()) {
    std::map<u32, double> func_shortest;
    Json::Value           func_shortest_value = shortest_dist_map[dst_s];
    std::vector<u32>      reachable;
    for (auto src_s : func_shortest_value.getMemberNames()) {
      func_shortest.insert(std::make_pair(
          std::stoi(src_s), func_shortest_value[src_s].asDouble()));
      reachable.push_back(std::stoi(src_s));
    }
    func_dist_map.insert(std::make_pair(std::stoi(dst_s), func_shortest));
    func_reachable_map.insert(std::make_pair(std::stoi(dst_s), reachable));
  }
  // update reachable function map
  for (auto dst_s : shortest_call_map.getMemberNames()) {
    Json::Value      func_shortest_value = shortest_call_map[dst_s];
    std::vector<u32> reachable;
    for (auto src_s : func_shortest_value.getMemberNames()) {
      reachable.push_back(std::stoi(src_s));
    }
    auto it = func_reachable_map.find(std::stoi(dst_s));

    if (it != func_reachable_map.end()) {
      it->second.insert(it->second.end(), reachable.begin(), reachable.end());
    } else {
      func_reachable_map.insert(std::make_pair(std::stoi(dst_s), reachable));
    }
  }

  initialized_bug_map();
}

void initialized_dist_map() {
  Json::Value   shortest_dist_map;
  Json::Reader  reader;
  std::string   temporary_dir = std::getenv("TMP_DIR"), errs;
  std::ifstream dist_map(temporary_dir + "/runtimes/calldst.json",
                         std::ifstream::binary);

  if (!reader.parse(dist_map, shortest_dist_map, false))
    PFATAL("Failed loading dist map !");

  for (auto dst_s : shortest_dist_map.getMemberNames()) {
    std::map<u32, double> func_shortest;
    Json::Value           func_shortest_value = shortest_dist_map[dst_s];

    for (auto src_s : func_shortest_value.getMemberNames()) {
      func_shortest.insert(std::make_pair(
          std::stoi(src_s), func_shortest_value[src_s].asDouble()));
    }
    func_dist_map.insert(std::make_pair(std::stoi(dst_s), func_shortest));
  }

  initialized_bug_map();
}

/*initialize target function map*/
void initialized_target_function_map() {
  Json::Value   funcid_targetid_map;
  Json::Reader  reader;
  std::string   temporary_dir = std::getenv("TMP_DIR"), errs;
  std::ifstream function_target_stream(temporary_dir + "/function2target.json",
                                       std::ifstream::binary);

  if (!reader.parse(function_target_stream, funcid_targetid_map, false))
    PFATAL("Failed loading dist map !");

  for (const auto &funcid : funcid_targetid_map.getMemberNames()) {
    std::string        funcid_str = funcid;
    const Json::Value &target_list_value = funcid_targetid_map[funcid];
    std::vector<u32>   target_list;
    for (const Json::Value &targetid : target_list_value) {
      target_list.push_back(targetid.asInt());
    }
    funcid2targetid_map[std::stoi(funcid_str)] = target_list;
  }


  std::ifstream fi(temporary_dir + "/target2function.csv");
  if (fi.is_open()) {
    std::string line;
    while (getline(fi, line)) {
      std::size_t dis_pos = line.find(",");
      std::string func_id = line.substr(dis_pos + 1, line.length() - dis_pos);
      std::string target_id = line.substr(0, dis_pos);
      targetid2funcid_map.emplace(atoi(target_id.c_str()),
                                  atoi(func_id.c_str()));
      // std::cout << target_id << " : " << func_id << "\n";
    }
  }
}
Targets get_func_target_group(u32 funcId) {
  std::vector<u32> result;

  auto targetIdsIter = funcid2targetid_map.find(funcId);

  if (targetIdsIter != funcid2targetid_map.end()) {
    result = targetIdsIter->second;
  }

  Targets res;
  res.size = result.size();
  res.targets = new u32[res.size];
  std::copy(result.begin(), result.end(), res.targets);

  return res;
}
Targets get_target_group(u32 targetId) {
  std::vector<u32> result;

  auto funcIdIter = targetid2funcid_map.find(targetId);
  ACTF("error at this point?");
  if (funcIdIter != targetid2funcid_map.end()) {
    u32 funcId = funcIdIter->second;

    auto targetIdsIter = funcid2targetid_map.find(funcId);

    if (targetIdsIter != funcid2targetid_map.end()) {
      result = targetIdsIter->second;
    }
  }

  Targets res;
  res.size = result.size();
  res.targets = new u32[res.size];
  std::copy(result.begin(), result.end(), res.targets);

  return res;
}
u32 get_funcid(u32 targetId) {

    try {
        if (targetid2funcid_map.empty()) {
            initialized_target_function_map();
        }
        auto funcIdIter = targetid2funcid_map.find(targetId);
        if (funcIdIter != targetid2funcid_map.end()) { 
            return funcIdIter->second; 
        }
        return FUNC_SIZE;
    } catch (const std::exception& e) {
        std::cerr << "get_funcid error: " << e.what() << std::endl;
        return FUNC_SIZE; 
    }
}

void free_target_group(Targets res) {
  delete[] res.targets;
}


const u32 *get_reachable_functions(u32 funcId, size_t *outSize) {
  auto it = func_reachable_map.find(funcId);
  if (it != func_reachable_map.end()) {
    *outSize = it->second.size();
    return it->second.data();
  }
  *outSize = 0;
  return nullptr;
}

static inline bool compareValues(
    const std::pair<std::uint32_t, std::uint32_t> &pair1,
    const std::pair<std::uint32_t, std::uint32_t> &pair2) {
  return pair1.second > pair2.second;  // sort descending
}

bool targetCompare(const std::pair<double, std::uint32_t> &pair1,
                   const std::pair<double, std::uint32_t> &pair2) {
  // Compare based on the first element (a)
  if (pair1.first < pair2.first)
    return true;
  else if (pair1.first > pair2.first)
    return false;

  // If the first elements are equal, compare based on the second element (b)
  return pair1.second < pair2.second;
}

// initialize target priority map
void initialized_target_priority_map(afl_state_t *afl) {
  if (unlikely(!afl->target_initial_priority)) {
    PFATAL("Failed loading target priority map !");
  }
  std::string   temporary_dir = std::getenv("TMP_DIR");
  std::ifstream tp(temporary_dir + "/target_priority.csv");
  // std::vector<std::pair<std::uint32_t, std::uint32_t>> target_priority_vec;
  u32 max_value = 0;
  if (tp.is_open()) {
    std::string line;
    while (getline(tp, line)) {
      std::size_t   p_pos = line.find(",");
      std::uint32_t target_id = atoi(line.substr(0, p_pos).c_str());
      std::uint32_t priority =
          (int)(100 * atof(line.substr(p_pos + 1, line.length()).c_str()));
      afl->target_initial_priority[target_id] = priority;
      afl->target_count++;
      // target_priority_vec.push_back(std::make_pair(target_id, priority));
      if (priority > max_value) {
        afl->valuable_target = target_id;
        max_value = priority;
      }
    }
  }
  /* initialize focused target based on priority */
  afl->valuable_function = get_funcid(afl->valuable_target);
  OKF("finish loading the target priority map...,valuable target is %d",
      afl->valuable_target);
  tp.close();
}

void write_target_priority_log(
    afl_state_t                                  *afl,
    std::vector<std::pair<double, std::uint32_t>> reached_bugs) {
  if (!afl->target_priority_log) {
    afl->target_priority_log =
        (u8 *)malloc(strlen((const char *)afl->out_dir) +
                     20);  // alloc_printf("%s/func_debug.log", afl->out_dir);
    sprintf((char *)afl->target_priority_log, "%s/target_score.log",
            afl->out_dir);
    afl->target_priority_fd = fopen((char *)afl->target_priority_log, "w");
  }
  u32 i = 0;
  if (reached_bugs.size()) {
    auto   now = std::chrono::system_clock::now();
    auto   duration = now.time_since_epoch();
    double normalized_metric = 0;
    u64    current_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(duration)
            .count() -
        afl->start_time;

    // u64 current_ms = get_cur_time() - afl->start_time;
    fprintf(afl->target_priority_fd,
            "[%02lld:%02lld:%02lld] : focus on function %d , max: %f , "
            "min: %f \n",
            current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
            (current_ms / 1000) % 60, afl->valuable_function,
            afl->max_target_priority, afl->min_target_priority);

    for (const auto &pair : reached_bugs) {
      if (i > 10) break;
      if (afl->max_target_priority == afl->min_target_priority) {
        normalized_metric = 100 + afl->focused_count[pair.second] * 100;
      } else {
        normalized_metric =
            (pair.first - afl->min_target_priority) * 100 /
                (afl->max_target_priority - afl->min_target_priority) +
            afl->focused_count[pair.second] * 100;
      }
      fprintf(afl->target_priority_fd,
              "target id: %d, metric: %f, focused count: %d, normalized score: "
              "%f \n",
              pair.second, pair.first, afl->focused_count[pair.second],
              normalized_metric);

      i++;
    }

    // std::cout << "for function " <<  func_id << ", update to s" << q2->id <<
    // ", distance " << dist2 << ".\n";
  }
}
void write_function_log(afl_state_t *afl, struct queue_entry *q1,
                        struct queue_entry *q2, u32 dist1, u32 dist2,
                        u32 func_id) {
  if (!afl->function_debug_log) {
    afl->function_debug_log =
        (u8 *)malloc(strlen((const char *)afl->out_dir) +
                     17);  // alloc_printf("%s/func_debug.log", afl->out_dir);
    sprintf((char *)afl->function_debug_log, "%s/func_debug.log", afl->out_dir);
    afl->function_debug_fd = fopen((char *)afl->function_debug_log, "w");
  }

  if (q2) {
    // u64 current_ms = get_cur_time_us() / 1000 - afl->start_time;

    fprintf(afl->function_debug_fd,
            "for function %d, update to s%d, distance %d.\n",
            // current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
            // (current_ms / 1000) % 60,
            func_id, q2->id, dist2);
    // std::cout << "for function " <<  func_id << ", update to s" << q2->id <<
    // ", distance " << dist2 << ".\n";
  }
}

/* wrapper to update top_rated_explore */
void update_bitmap_score_explore(afl_state_t *afl) {
  if (!afl->virgin_funcs) return;

  if (!afl->shortest_dist) {
    afl->shortest_dist = (u32 *)ck_alloc(sizeof(u32) * FUNC_SIZE);

    for (u32 i = 0; i < FUNC_SIZE; i++)
      afl->shortest_dist[i] = UNREACHABLE_DIST;
  }

  for (u32 i = 0; i < FUNC_SIZE; i++) {
    // there are unvisited label in this function and it's not touched yet
    if (!unvisited_func_map[i] || afl->virgin_funcs[i]) continue;

    if (afl->top_rated_explore[i]) {
      // if (top_rated_explore[i]->favored)
      //   top_rated_explore[i]->favored = 0;
      if (afl->top_rated_explore[i]->fuzz_level)
        afl->top_rated_explore[i] = NULL;
    }
    // iterate over queue to find a seed with shortest distance
    for (u32 sid = 0; sid < afl->queued_items; sid++) {
      struct queue_entry *q = afl->queue_buf[sid];
      // skip fuzzed seed or initial seed when its' trace_func not updated
      if (q->fuzz_level || !q->trace_func) continue;
      u32    fexp_score = 0;
      double shortest_dist = UNREACHABLE_DIST;
      u64    fav_factor = q->len * q->exec_us;
      // iterate over shortest map
      for (auto iter = func_dist_map[i].begin(); iter != func_dist_map[i].end();
           iter++) {
        if (q->trace_func[iter->first])
          if (iter->second < shortest_dist) shortest_dist = iter->second;
      }

      if (shortest_dist != UNREACHABLE_DIST) fexp_score = shortest_dist * 100;

      // update top_rated_explore
      if (fexp_score) {
        if (!afl->top_rated_explore[i]) {
          write_function_log(afl, afl->top_rated_explore[i], q,
                             afl->shortest_dist[i], fexp_score / 100, i);
          afl->top_rated_explore[i] = q;
          afl->shortest_dist[i] = fexp_score;
        } else {
          if (fexp_score < afl->shortest_dist[i]) {
            write_function_log(afl, afl->top_rated_explore[i], q,
                               afl->shortest_dist[i], fexp_score / 100, i);
            afl->top_rated_explore[i] = q;
            afl->shortest_dist[i] = fexp_score;
          }
          if (fexp_score == afl->shortest_dist[i] &&
              fav_factor < afl->top_rated_explore[i]->exec_us *
                               afl->top_rated_explore[i]->len) {
            write_function_log(afl, afl->top_rated_explore[i], q,
                               afl->shortest_dist[i], fexp_score / 100, i);
            afl->top_rated_explore[i] = q;
            afl->shortest_dist[i] = fexp_score;
          }
        }
      }
    }
  }
}

/* wrapper to update exploit threshould */
void target_ranking_original(afl_state_t *afl) {
  std::vector<std::uint32_t> reached_bugs;
  std::uint32_t              max_value = 1;

  if (!afl->reach_bits_count || !afl->trigger_bits_count) return;

  for (u32 i = 0; i < VMAP_COUNT; i++) {
    if (afl->reach_bits_count[i] && !afl->trigger_bits_count[i]) {
      reached_bugs.push_back(afl->reach_bits_count[i]);

      if (max_value < afl->reach_bits_count[i])
        max_value = afl->reach_bits_count[i];
    }
  }
  std::sort(reached_bugs.begin(), reached_bugs.end());
  if (max_value != 1) {
    float rate = afl->pending_not_fuzzed / afl->queued_items;

    if (rate < 0.2)
      rate = 0.2;

    else if (rate < 0.5)
      rate = 0.15;

    else
      rate = 0.1;

    afl->exploit_threshould = reached_bugs[reached_bugs.size() * rate];
  }
}

void target_ranking(afl_state_t *afl) {
  // std::vector<std::pair<std::uint32_t, std::uint32_t>> reached_bugs;
  std::vector<std::pair<double, std::uint32_t>> reached_bugs;
  std::vector<std::uint32_t>                    normalized_reached_bugs;
  double                                        normalized_metric = 0;
  double                                        metric = 0;
  std::unordered_map<uint32_t, double>          target_score;
  std::unordered_map<uint32_t, double>          function_score;
  std::unordered_map<uint32_t, uint32_t>        function_iterations;
  double                                        min_value = 0xffffffff;
  if (!afl->reach_bits_count || !afl->trigger_bits_count ||
      !afl->unique_reach_bits_count)
    return;
  afl->max_target_priority = 0;
  afl->min_target_priority = 0xffffffff;
  u32 min_target_metric = 0xffffffff;
  for (u32 i = 0; i < afl->target_count; i++) {
    if (afl->unique_reach_bits_count[i] && afl->reach_bits_count[i] &&
        !afl->trigger_bits_count[i]) {
      metric = 100 * afl->unique_reach_bits_count[i] /
               (afl->target_initial_priority[i] + 1);
      metric = log(metric + 3);
      if (metric > afl->max_target_priority) {
        afl->max_target_priority = metric;
      }
      if (metric < afl->min_target_priority) {
        afl->min_target_priority = metric;
      }
      reached_bugs.push_back(std::make_pair(metric, i));
    }
  }

  std::sort(reached_bugs.begin(), reached_bugs.end(), targetCompare);

  // normalized the first metric to 0-100
  if (afl->disable_priority_choice != DISABLE_TARGET) {
    for (auto &m : reached_bugs) {
      if (afl->max_target_priority == afl->min_target_priority) {
        normalized_metric = 100 + afl->focused_count[m.second] * 100;
      } else {
        normalized_metric =
            (m.first - afl->min_target_priority) * 100 /
                (afl->max_target_priority - afl->min_target_priority) +
            afl->focused_count[m.second] * 100;
      }
      // update target_score

      if (normalized_metric < min_value && get_funcid(m.second) != FUNC_SIZE) {
        min_value = normalized_metric;
        afl->valuable_target = m.second;
      }
      normalized_reached_bugs.push_back((u32)normalized_metric);
    }

    std::sort(normalized_reached_bugs.begin(), normalized_reached_bugs.end());
    if (min_value != 0xffffffff) {
      float rate = afl->pending_not_fuzzed / afl->queued_items;

      if (rate < 0.2)
        rate = 0.2;

      else if (rate < 0.5)
        rate = 0.15;

      else
        rate = 0.1;

      afl->exploit_threshould =
          normalized_reached_bugs[normalized_reached_bugs.size() * rate];
    }

  } else {
    for (u32 i = 0; i < afl->target_count; i++) {
      if (afl->target_initial_priority[i] == 0) continue;
      // compute target metric
      u32 target_metric = 0;
      target_metric = afl->reach_bits_count[i];
      if (target_metric < min_target_metric && get_funcid(i) != FUNC_SIZE) {
        min_target_metric = target_metric;
        afl->valuable_target = i;
      }
      normalized_reached_bugs.push_back(target_metric);
    }
  }

  // std::sort(normalized_reached_bugs.begin(), normalized_reached_bugs.end());
  write_target_priority_log(afl, reached_bugs);
}

void add_to_vector(u32 length) {
  seed_length.push_back(length);
}

u32 get_pos_length(u32 pos) {
  sort(seed_length.begin(), seed_length.end());
  return seed_length[pos];
}



#ifdef __cplusplus
}
#endif
